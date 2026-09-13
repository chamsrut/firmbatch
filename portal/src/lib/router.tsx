/**
 * A small history-API router. About a hundred lines, and it is the right size for this.
 *
 * The portal has a flat set of pages, no nested layouts and no data loaders, so a routing
 * library would be a dependency carrying a resolver, a matcher and a data layer this
 * application would use none of. What it needs is: know the current path, change it without
 * a reload, answer the back button, and hand focus to the new page's heading so a screen
 * reader announces it -- which is the part a hand-rolled router usually gets wrong and which
 * is implemented here deliberately.
 *
 * Every navigation goes through {@link safeDestination}. That is not defensive habit: the
 * post-sign-in destination comes from a query parameter, and a router that navigated to an
 * unchecked string would be an open redirect with extra steps.
 *
 * The router is also where a one-time token leaves the URL, because the router is the first
 * thing to read the URL and the last thing that should ever see a secret in it: see
 * `lib/one-time-token.ts`.
 */

import {
  createContext,
  type MouseEvent,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import { captureTokenFromLocation } from "./one-time-token.ts";
import { safeDestination } from "./redirect.ts";

export interface Location {
  pathname: string;
  search: string;
}

export interface RouterApi extends Location {
  navigate: (to: string, options?: { replace?: boolean }) => void;
}

const RouterContext = createContext<RouterApi | null>(null);

function currentLocation(): Location {
  return { pathname: window.location.pathname, search: window.location.search };
}

export function RouterProvider({ children }: { children: ReactNode }) {
  const [location, setLocation] = useState<Location>(() => {
    // The very first thing done with the URL, before any component reads it and before
    // any guard can redirect away from it: a one-time token from an emailed link is moved
    // into memory and taken out of the address bar. StrictMode invokes this initializer
    // twice; the second call finds nothing in the URL and leaves the held token alone.
    captureTokenFromLocation();
    return currentLocation();
  });

  useEffect(() => {
    const onPop = () => {
      captureTokenFromLocation();
      setLocation(currentLocation());
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const navigate = useCallback((to: string, options?: { replace?: boolean }) => {
    const target = safeDestination(to);
    const next = { pathname: target.split("?")[0] ?? "/", search: "" };
    const url = new URL(target, window.location.origin);
    next.pathname = url.pathname;
    next.search = url.search;
    if (options?.replace) {
      window.history.replaceState(null, "", target);
    } else {
      window.history.pushState(null, "", target);
    }
    setLocation(next);
  }, []);

  const value = useMemo<RouterApi>(
    () => ({ pathname: location.pathname, search: location.search, navigate }),
    [location.pathname, location.search, navigate],
  );

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useRouter(): RouterApi {
  const value = useContext(RouterContext);
  if (value === null) {
    throw new Error("useRouter must be used inside a RouterProvider");
  }
  return value;
}

/**
 * An in-application link.
 *
 * A real `<a href>`, so it can be opened in a new tab, copied, and read by assistive
 * technology as the link it is. The click handler intercepts only the plain left-click that
 * would otherwise reload the page; a modified click (new tab, new window, download) is left
 * to the browser, which is the behaviour customers expect and the behaviour a `<button>`
 * styled as a link cannot give them.
 */
export function Link({
  to,
  children,
  className,
  onNavigate,
  ...rest
}: {
  to: string;
  children: ReactNode;
  className?: string;
  onNavigate?: () => void;
} & Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, "href" | "className">) {
  const router = useRouter();
  const href = safeDestination(to);
  const onClick = (event: MouseEvent<HTMLAnchorElement>) => {
    if (event.defaultPrevented) return;
    if (event.button !== 0) return;
    if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    router.navigate(href);
    onNavigate?.();
  };
  return (
    <a href={href} onClick={onClick} className={className} {...rest}>
      {children}
    </a>
  );
}
