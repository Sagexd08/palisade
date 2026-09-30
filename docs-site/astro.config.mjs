// @ts-check
import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

// Deployed under the marketing site at /docs/ on try.arpankernel.com.
export default defineConfig({
  site: "https://try.arpankernel.com",
  base: "/docs",
  trailingSlash: "always",
  outDir: "./dist",
  integrations: [
    starlight({
      title: "Palisade",
      description:
        "We're building the AI safety engineer for your codebase. v1 ships today: a precise static detector for untrusted-input → model → dangerous-capability paths in Python and JS/TS.",
      tagline: "We're building the AI safety engineer for your codebase.",
      logo: { src: "./src/assets/logo.svg", replacesTitle: false },
      social: { github: "https://github.com/arpankernel/palisade" },
      customCss: ["./src/styles/theme.css"],
      editLink: {
        baseUrl: "https://github.com/arpankernel/palisade/edit/main/docs-site/",
      },
      components: {
        SiteTitle: "./src/components/SiteTitle.astro",
      },
      sidebar: [
        { label: "Start here", items: [
          { label: "Overview", link: "/" },
          { label: "Getting started", slug: "getting-started" },
          { label: "End-to-end tutorial", slug: "tutorial" },
        ]},
        { label: "Reference", items: [
          { label: "Architecture", slug: "architecture" },
          { label: "CLI reference", slug: "cli-reference" },
          { label: "Connect (GitHub, Slack, LLM)", slug: "connect" },
          { label: "Judgment layer (advisory)", slug: "judgment-layer" },
          { label: "Rules reference", slug: "rules-reference" },
        ]},
        { label: "Going further", items: [
          { label: "For AI agents", slug: "agents" },
          { label: "Proof scans", slug: "proof-scans" },
          { label: "Roadmap", slug: "roadmap" },
        ]},
      ],
    }),
  ],
});
