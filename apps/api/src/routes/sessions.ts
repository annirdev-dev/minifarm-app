import type { FastifyInstance } from "fastify";
import { randomUUID } from "node:crypto";
import { prisma } from "@devicefarm/database";
import {
  startSessionSchema,
  touchInputSchema,
  swipeInputSchema,
  keyInputSchema,
  textInputSchema,
  rotateSchema,
  paginationQuerySchema,
  paginate,
  offsetFor,
  ForbiddenError,
  NotFoundError,
  ConflictError,
} from "@devicefarm/shared";
import { BUCKETS, objectKeyForScreenshot, presignedGetUrl, uploadObject } from "@devicefarm/storage";
import { authenticate, requireOrgMembership } from "../auth/middleware";
import { sessionLifecycleQueue, sessionCleanupQueue } from "../lib/queues";
import { resolveWorkerBaseUrl } from "../lib/worker-url";
import { userOrgIds } from "../lib/tenant";
import { PLAN_DEFINITIONS } from "@devicefarm/shared";

async function loadRunningInstanceContext(sessionId: string, userId: string, isPlatformAdmin: boolean) {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    include: { emulatorInstance: { include: { computeHost: true } } },
  });
  if (!session) throw new NotFoundError("Session");
  if (!isPlatformAdmin) {
    const memberships = await userOrgIds(userId);
    if (!memberships.includes(session.organizationId)) throw new ForbiddenError();
  }
  if (!session.emulatorInstance) throw new ConflictError("Session has no running instance");

  const baseUrl = resolveWorkerBaseUrl(session.emulatorInstance.computeHost);
  if (!baseUrl) throw new ConflictError("Could not reach this session's compute host");

  return { session, instanceId: session.emulatorInstance.id, baseUrl };
}

// Prisma's BigInt (AppVersion.fileSizeBytes) isn't JSON-serializable -
// stringify it wherever a session's nested appVersion is returned.
function serializeSession<T extends { appVersion?: { fileSizeBytes: bigint } | null }>(session: T) {
  if (!session.appVersion) return session;
  return { ...session, appVersion: { ...session.appVersion, fileSizeBytes: session.appVersion.fileSizeBytes.toString() } };
}

async function callWorker(baseUrl: string, path: string, init?: RequestInit) {
  const res = await fetch(`${baseUrl}${path}`, { ...init, headers: { "content-type": "application/json", ...init?.headers } });
  if (!res.ok) throw new Error(`Worker call failed (${res.status}): ${await res.text()}`);
  return res;
}

export async function sessionsRoutes(app: FastifyInstance) {
  app.addHook("preHandler", authenticate);

  app.get("/api/sessions", async (req) => {
    const query = paginationQuerySchema.parse(req.query);
    const { projectId, status } = req.query as { projectId?: string; status?: string };
    const orgIds = await userOrgIds(req.user!.userId);

    const where = {
      organizationId: { in: orgIds },
      projectId: projectId || undefined,
      status: (status as never) || undefined,
    };
    const [items, total] = await Promise.all([
      prisma.session.findMany({
        where,
        include: { app: true, deviceProfile: true, appVersion: true, user: { select: { id: true, name: true, email: true } } },
        orderBy: { createdAt: "desc" },
        skip: offsetFor(query),
        take: query.pageSize,
      }),
      prisma.session.count({ where }),
    ]);
    return paginate(items.map(serializeSession), total, query);
  });

  app.post("/api/sessions", async (req, reply) => {
    const input = startSessionSchema.parse(req.body);
    const project = await prisma.project.findUnique({ where: { id: input.projectId } });
    if (!project) throw new NotFoundError("Project");
    await requireOrgMembership(req, project.organizationId, ["OWNER", "ADMIN", "MEMBER"]);

    const [appVersion, deviceProfile, subscription] = await Promise.all([
      prisma.appVersion.findUnique({ where: { id: input.appVersionId }, include: { app: true } }),
      prisma.deviceProfile.findUnique({ where: { id: input.deviceProfileId } }),
      prisma.subscription.findUnique({ where: { organizationId: project.organizationId } }),
    ]);
    if (!appVersion || appVersion.appId !== input.appId) throw new NotFoundError("App version");
    if (appVersion.status !== "READY") throw new ConflictError(`App version is not ready to run (status=${appVersion.status})`);
    if (!deviceProfile || !deviceProfile.isEnabled) throw new NotFoundError("Device profile");

    const plan = PLAN_DEFINITIONS[subscription?.plan ?? "FREE"];
    if (subscription && plan.deviceMinutesPerMonth !== null && subscription.deviceMinutesUsed >= plan.deviceMinutesPerMonth) {
      throw new ConflictError(`Plan limit reached: ${plan.name} includes ${plan.deviceMinutesPerMonth} device-minutes/month`);
    }

    const session = await prisma.session.create({
      data: {
        id: randomUUID(),
        userId: req.user!.userId,
        organizationId: project.organizationId,
        projectId: input.projectId,
        appId: input.appId,
        appVersionId: input.appVersionId,
        deviceProfileId: input.deviceProfileId,
        status: "CREATING",
      },
    });

    await sessionLifecycleQueue().add("start", { sessionId: session.id }, { removeOnComplete: true, removeOnFail: 20 });
    await prisma.auditLog.create({
      data: { organizationId: project.organizationId, actorUserId: req.user!.userId, action: "session.started", targetType: "session", targetId: session.id },
    });

    return reply.code(201).send({ session });
  });

  app.get("/api/sessions/:id", async (req) => {
    const { id } = req.params as { id: string };
    const session = await prisma.session.findUnique({
      where: { id },
      include: { app: true, appVersion: true, deviceProfile: true, emulatorInstance: { include: { computeHost: true } } },
    });
    if (!session) throw new NotFoundError("Session");
    if (!req.user!.isPlatformAdmin) {
      const orgIds = await userOrgIds(req.user!.userId);
      if (!orgIds.includes(session.organizationId)) throw new ForbiddenError();
    }
    return { session: serializeSession(session) };
  });

  app.post("/api/sessions/:id/stop", async (req) => {
    const { id } = req.params as { id: string };
    const session = await prisma.session.findUnique({ where: { id } });
    if (!session) throw new NotFoundError("Session");
    if (!req.user!.isPlatformAdmin) await requireOrgMembership(req, session.organizationId);

    await sessionCleanupQueue().add("cleanup", { sessionId: id, reason: "user_requested" }, { removeOnComplete: true, removeOnFail: 20 });
    return { ok: true };
  });

  app.delete("/api/sessions/:id", async (req) => {
    const { id } = req.params as { id: string };
    const session = await prisma.session.findUnique({ where: { id } });
    if (!session) throw new NotFoundError("Session");
    if (!req.user!.isPlatformAdmin) await requireOrgMembership(req, session.organizationId);
    if (session.status !== "STOPPED" && session.status !== "FAILED") {
      throw new ConflictError("Stop the session before deleting it");
    }

    await prisma.session.delete({ where: { id } });
    await prisma.auditLog.create({
      data: { organizationId: session.organizationId, actorUserId: req.user!.userId, action: "session.deleted", targetType: "session", targetId: id },
    });
    return { ok: true };
  });

  app.post("/api/sessions/:id/restart", async (req) => {
    const { id } = req.params as { id: string };
    const { instanceId, baseUrl } = await loadRunningInstanceContext(id, req.user!.userId, req.user!.isPlatformAdmin);
    await callWorker(baseUrl, `/instances/${instanceId}/restart`, { method: "POST" });
    await prisma.session.update({ where: { id }, data: { lastActivityAt: new Date() } });
    return { ok: true };
  });

  app.post("/api/sessions/:id/rotate", async (req) => {
    const { id } = req.params as { id: string };
    const body = rotateSchema.parse(req.body);
    const { instanceId, baseUrl } = await loadRunningInstanceContext(id, req.user!.userId, req.user!.isPlatformAdmin);
    await callWorker(baseUrl, `/instances/${instanceId}/rotate`, { method: "POST", body: JSON.stringify(body) });
    return { ok: true };
  });

  app.post("/api/sessions/:id/input/touch", async (req) => {
    const { id } = req.params as { id: string };
    const body = touchInputSchema.parse(req.body);
    const { instanceId, baseUrl } = await loadRunningInstanceContext(id, req.user!.userId, req.user!.isPlatformAdmin);
    await callWorker(baseUrl, `/instances/${instanceId}/input/touch`, { method: "POST", body: JSON.stringify(body) });
    await prisma.session.update({ where: { id }, data: { lastActivityAt: new Date() } });
    return { ok: true };
  });

  app.post("/api/sessions/:id/input/swipe", async (req) => {
    const { id } = req.params as { id: string };
    const body = swipeInputSchema.parse(req.body);
    const { instanceId, baseUrl } = await loadRunningInstanceContext(id, req.user!.userId, req.user!.isPlatformAdmin);
    await callWorker(baseUrl, `/instances/${instanceId}/input/swipe`, { method: "POST", body: JSON.stringify(body) });
    await prisma.session.update({ where: { id }, data: { lastActivityAt: new Date() } });
    return { ok: true };
  });

  app.post("/api/sessions/:id/input/key", async (req) => {
    const { id } = req.params as { id: string };
    const body = keyInputSchema.parse(req.body);
    const { instanceId, baseUrl } = await loadRunningInstanceContext(id, req.user!.userId, req.user!.isPlatformAdmin);
    await callWorker(baseUrl, `/instances/${instanceId}/input/key`, { method: "POST", body: JSON.stringify(body) });
    await prisma.session.update({ where: { id }, data: { lastActivityAt: new Date() } });
    return { ok: true };
  });

  app.post("/api/sessions/:id/input/text", async (req) => {
    const { id } = req.params as { id: string };
    const body = textInputSchema.parse(req.body);
    const { instanceId, baseUrl } = await loadRunningInstanceContext(id, req.user!.userId, req.user!.isPlatformAdmin);
    await callWorker(baseUrl, `/instances/${instanceId}/input/text`, { method: "POST", body: JSON.stringify(body) });
    await prisma.session.update({ where: { id }, data: { lastActivityAt: new Date() } });
    return { ok: true };
  });

  app.post("/api/sessions/:id/screenshot", async (req) => {
    const { id } = req.params as { id: string };
    const { instanceId, baseUrl } = await loadRunningInstanceContext(id, req.user!.userId, req.user!.isPlatformAdmin);

    const res = await callWorker(baseUrl, `/instances/${instanceId}/screenshot`);
    const buffer = Buffer.from(await res.arrayBuffer());
    const session = await prisma.session.findUniqueOrThrow({ where: { id }, include: { deviceProfile: true } });

    const screenshot = await prisma.screenshot.create({
      data: {
        sessionId: id,
        storageKey: "",
        width: session.deviceProfile.resolutionWidth,
        height: session.deviceProfile.resolutionHeight,
        fileSizeBytes: buffer.length,
      },
    });
    const storageKey = objectKeyForScreenshot(id, screenshot.id);
    await uploadObject(BUCKETS.screenshots, storageKey, buffer, res.headers.get("content-type") ?? "image/png");
    await prisma.screenshot.update({ where: { id: screenshot.id }, data: { storageKey } });

    const url = await presignedGetUrl(BUCKETS.screenshots, storageKey, 900);
    return { screenshot: { ...screenshot, storageKey, url } };
  });

  app.get("/api/sessions/:id/screenshots", async (req) => {
    const { id } = req.params as { id: string };
    const session = await prisma.session.findUnique({ where: { id } });
    if (!session) throw new NotFoundError("Session");
    if (!req.user!.isPlatformAdmin) await requireOrgMembership(req, session.organizationId);

    const screenshots = await prisma.screenshot.findMany({ where: { sessionId: id }, orderBy: { createdAt: "desc" } });
    const withUrls = await Promise.all(
      screenshots.map(async (s) => ({ ...s, url: await presignedGetUrl(BUCKETS.screenshots, s.storageKey, 900) })),
    );
    return { screenshots: withUrls };
  });

  app.get("/api/sessions/:id/events", async (req) => {
    const { id } = req.params as { id: string };
    const session = await prisma.session.findUnique({ where: { id } });
    if (!session) throw new NotFoundError("Session");
    if (!req.user!.isPlatformAdmin) await requireOrgMembership(req, session.organizationId);

    const events = await prisma.sessionEvent.findMany({ where: { sessionId: id }, orderBy: { createdAt: "asc" } });
    return { events };
  });

  app.get("/api/sessions/:id/logs", async (req) => {
    const { id } = req.params as { id: string };
    const session = await prisma.session.findUnique({ where: { id } });
    if (!session) throw new NotFoundError("Session");
    if (!req.user!.isPlatformAdmin) await requireOrgMembership(req, session.organizationId);

    const { source, level, search } = req.query as { source?: string; level?: string; search?: string };
    const query = paginationQuerySchema.parse(req.query);
    const where = {
      sessionId: id,
      source: (source as never) || undefined,
      level: (level as never) || undefined,
      message: search ? { contains: search, mode: "insensitive" as const } : undefined,
    };
    const [items, total] = await Promise.all([
      prisma.log.findMany({ where, orderBy: { createdAt: "asc" }, skip: offsetFor(query), take: query.pageSize }),
      prisma.log.count({ where }),
    ]);
    return paginate(items, total, query);
  });
}
