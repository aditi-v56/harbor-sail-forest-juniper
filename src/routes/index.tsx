import { createFileRoute } from "@tanstack/react-router";
import { SocConsole } from "@/components/soc/console";

export const Route = createFileRoute("/")({ component: Home });

function Home() {
  return <SocConsole />;
}
