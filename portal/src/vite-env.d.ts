/// <reference types="vite/client" />

/**
 * Side-effect stylesheet imports. Vite handles these; TypeScript needs telling that a `.css`
 * import is a module with no exports rather than a missing file.
 */
declare module "*.css";
