import { createFileRoute } from "@tanstack/react-router";
import { BreachStory } from "@/components/breach-story";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "The Forest Fire of Cyber Breaches" },
      { name: "description", content: "An interactive explainer about heavy-tailed cyber breaches, systemic risk, and why one breach can outweigh a thousand." },
      { property: "og:title", content: "The Forest Fire of Cyber Breaches" },
      { property: "og:description", content: "Play with real breach data, grow a digital forest fire, and explore a thousand possible futures." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

function Index() {
  return <BreachStory />;
}
