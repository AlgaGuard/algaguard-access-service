import { Router } from "express";
import { z } from "zod";
import { AccessStore } from "./domain.js";
export const router = Router();
const store = new AccessStore();
router.post("/organizations", (request, response) => {
  const input = z
    .object({
      name: z.string().min(1).max(120),
      ownerSubjectId: z.string().min(1),
    })
    .parse(request.body);
  response
    .status(201)
    .json(store.createOrganization(input.name, input.ownerSubjectId));
});
router.get("/organizations", (request, response) => {
  const subjectId = z.string().optional().parse(request.query.subjectId);
  response.json({ items: store.organizationsFor(subjectId) });
});
router.post("/organizations/:id/memberships", (request, response) => {
  const input = z
    .object({
      subjectId: z.string().min(1),
      role: z.enum(["OWNER", "ADMIN", "OPERATOR", "VIEWER"]),
    })
    .parse(request.body);
  if (!store.organizations.has(request.params.id))
    return response.status(404).json({ status: 404 });
  return response
    .status(201)
    .json(store.addMembership(request.params.id, input.subjectId, input.role));
});
router.post("/organizations/:id/invitations", (request, response) => {
  const input = z
    .object({
      email: z.string().email(),
      expiresInSeconds: z.number().int().min(60).max(604800).default(86400),
    })
    .parse(request.body);
  if (!store.organizations.has(request.params.id))
    return response.status(404).json({ status: 404 });
  return response.status(201).json({
    invitationToken: store.invite(
      request.params.id,
      input.email,
      input.expiresInSeconds * 1000,
    ),
    expiresInSeconds: input.expiresInSeconds,
  });
});
router.post("/authorizations/subscriptions", (request, response) => {
  const input = z
    .object({
      subjectId: z.string(),
      resourceType: z.enum(["organization", "device", "current-user"]),
      resourceId: z.string().uuid().optional(),
    })
    .parse(request.body);
  response.json({
    allowed: store.authorizeSubscription(
      input.subjectId,
      input.resourceType,
      input.resourceId,
    ),
  });
});
