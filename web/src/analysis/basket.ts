// F-006 T-06 (F-006-AC-10, AC-12; design §3.2, §4): the comparison basket.
// "Add to comparison" on run and aggregate pages collects items here, a
// per-viewer convenience in the browser's storage (it can be empty or
// unavailable: every access is guarded); the comparison itself is its
// address, /analyses/compare?item=…, which anyone who sees every item can
// open. Nothing is stored on the server (OQ5).

import { useEffect, useState } from "react";

const KEY = "fair.compare.items";
export const MAX_ITEMS = 6;

/** A run's control set ("run:<id>:<set>") or an aggregate ("aggregate:<id>"). */
export type Item = string;

export function runItem(id: string, set: string): Item {
  return `run:${id}:${set}`;
}

export function aggregateItem(id: string): Item {
  return `aggregate:${id}`;
}

/** The comparison's address. */
export function compareHref(items: Item[]): string {
  const q = new URLSearchParams();
  for (const i of items) q.append("item", i);
  return `/analyses/compare?${q.toString()}`;
}

function read(): Item[] {
  try {
    const v = JSON.parse(window.localStorage.getItem(KEY) ?? "[]") as unknown;
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, MAX_ITEMS) : [];
  } catch {
    return [];
  }
}

function write(items: Item[]) {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(items));
  } catch {
    // Storage unavailable: the basket lasts as long as the page.
  }
  window.dispatchEvent(new Event("fair-basket"));
}

let memory: Item[] | null = null;

export function basketItems(): Item[] {
  const stored = read();
  return stored.length > 0 || memory === null ? stored : memory;
}

export function addToBasket(item: Item): Item[] {
  const items = basketItems().filter((i) => i !== item);
  items.push(item);
  const kept = items.slice(-MAX_ITEMS);
  memory = kept;
  write(kept);
  return kept;
}

export function clearBasket() {
  memory = [];
  write([]);
}

/** The basket, following changes from this page and others. */
export function useBasket(): Item[] {
  const [items, setItems] = useState<Item[]>(() => basketItems());
  useEffect(() => {
    const update = () => setItems(basketItems());
    window.addEventListener("fair-basket", update);
    window.addEventListener("storage", update);
    return () => {
      window.removeEventListener("fair-basket", update);
      window.removeEventListener("storage", update);
    };
  }, []);
  return items;
}
