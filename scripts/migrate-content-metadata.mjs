import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const blogDirectory = path.join(root, "src", "content", "blog");

const contentTypes = new Map([
  ["security-research-index", "interactive-atlas"],
  ["backup-restore-privileges-lab", "lab"],
  ["reproducible-windows-malware-analysis-lab", "lab"],
  ["authentication-coercion-petitpotam-relay-boundaries", "vulnerability"],
  ["print-spooler-boundaries-and-printnightmare", "vulnerability"],
]);

const files = (await readdir(blogDirectory))
  .filter((file) => /\.(?:md|mdx)$/i.test(file))
  .sort();

let changed = 0;

for (const file of files) {
  const filePath = path.join(blogDirectory, file);
  const source = await readFile(filePath, "utf8");
  const match = source.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n/);

  if (!match) {
    throw new Error(`Missing frontmatter delimiters: ${file}`);
  }

  const slug = file.replace(/\.(?:md|mdx)$/i, "");
  const frontmatter = match[1];
  const additions = [];

  if (!/^content_type:/m.test(frontmatter)) {
    additions.push(
      `content_type: ${JSON.stringify(contentTypes.get(slug) ?? "concept")}`,
    );
  }
  if (!/^status:/m.test(frontmatter)) {
    additions.push('status: "preliminary"');
  }
  if (!/^evidence_level:/m.test(frontmatter)) {
    additions.push('evidence_level: "unverified"');
  }

  if (!additions.length) continue;

  const insertionPoint = /^author:.*$/m.test(frontmatter)
    ? frontmatter.replace(/^(author:.*)$/m, `$1\n${additions.join("\n")}`)
    : `${frontmatter}\n${additions.join("\n")}`;

  const next = source.replace(frontmatter, insertionPoint);
  await writeFile(filePath, next, "utf8");
  changed += 1;
}

console.log(
  `Content metadata migration complete: ${changed} changed, ${files.length - changed} already current.`,
);
