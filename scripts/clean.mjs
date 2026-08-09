import { rmSync } from "node:fs";

for (const directory of ["../dist", "../dist-tsc"]) {
	rmSync(new URL(directory, import.meta.url), { force: true, recursive: true });
}
