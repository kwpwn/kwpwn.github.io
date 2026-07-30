import { readdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const root = process.cwd();
const oldUrl = "https://www.microsoft.com/msrc/security-guidance";
const newUrl = "https://msrc.microsoft.com/update-guide/";
const blogDirectory = path.join(root, "src", "content", "blog");
const candidates = [
  path.join(root, "scripts", "generate-yunolay-lessons.mjs"),
  ...(await readdir(blogDirectory))
    .filter((file) => /\.(?:md|mdx)$/i.test(file))
    .map((file) => path.join(blogDirectory, file)),
];

let replacements = 0;
let changedFiles = 0;

for (const filePath of candidates) {
  const source = await readFile(filePath, "utf8");
  const matches = source.split(oldUrl).length - 1;
  if (!matches) continue;

  await writeFile(filePath, source.replaceAll(oldUrl, newUrl), "utf8");
  replacements += matches;
  changedFiles += 1;
}

console.log(
  `Source URL migration complete: ${replacements} replacements in ${changedFiles} files.`,
);
