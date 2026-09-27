import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { analyzeEmailLocal } from "./orchestrator";

const Payload = z.object({
  subject: z.string(),
  body: z.string(),
  sender: z.string(),
  headers: z.string(),
});

export const analyzeReportedEmail = createServerFn({ method: "POST" })
  .inputValidator(Payload)
  .handler(async ({ data }) => {
    return analyzeEmailLocal(data);
  });
