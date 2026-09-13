/**
 * The entry point. Mounts the application; contains no logic worth testing on its own.
 */

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App.tsx";
import { SessionProvider } from "./auth/session.tsx";
import { RouterProvider } from "./lib/router.tsx";
import "./styles.css";

const container = document.getElementById("root");
if (container === null) {
  throw new Error("the portal needs a #root element to mount into");
}

createRoot(container).render(
  <StrictMode>
    <RouterProvider>
      <SessionProvider>
        <App />
      </SessionProvider>
    </RouterProvider>
  </StrictMode>,
);
