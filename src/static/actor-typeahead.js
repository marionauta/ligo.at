/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2026 Jake Lazaroff
 * Copyright (c) 2026 ligo.at contributors
 *
 * Changes
 *   2026-03-19
 *     New: Attribute `client` to send via the `X-Client` HTTP header.
 *     Fix: Hide avatars with no `src`.
 *   2026-03-17
 *     Fix: Abort previous HTTP request before starting the next.
 *     New: Add 250ms debounce to oninput.
 *     New: `host` attribute can be set to "location" to use window.location.
 *   2026-03-15
 *     Fix: Correctly count rows of actors.
 *     Fix: Disable browser autocomplete to not collide with the typeahead.
 *     Fix: Remove hardcoded `font-family`.
 *     New: You can press `Enter` while on the field to send the form.
 *     New: You can press `ArrowDown` while on the field to open the dropdown menu.
 */

const template = document.createElement("template");
template.innerHTML = `
  <slot></slot>

  <ul class="menu" part="menu"></ul>

  <style>
    :host {
      --color-background-inherited: var(--color-background, #ffffff);
      --color-border-inherited: var(--color-border, #00000022);
      --color-shadow-inherited: var(--color-shadow, #000000);
      --color-hover-inherited: var(--color-hover, #00000011);
      --color-avatar-fallback-inherited: var(--color-avatar-fallback, #00000022);
      --radius-inherited: var(--radius, 8px);
      --padding-menu-inherited: var(--padding-menu, 4px);
      display: block;
      position: relative;
    }

    *, *::before, *::after {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    .menu {
      display: flex;
      flex-direction: column;
      position: absolute;
      left: 0;
      margin-top: 4px;
      width: 100%;
      list-style: none;
      overflow: hidden;
      background-color: var(--color-background-inherited);
      background-clip: padding-box;
      border: 1px solid var(--color-border-inherited);
      border-radius: var(--radius-inherited);
      box-shadow: 0 6px 6px -4px rgb(from var(--color-shadow-inherited) r g b / 20%);
      padding: var(--padding-menu-inherited);
    }

    .menu:empty {
      display: none;
    }

    .user {
      all: unset;
      box-sizing: border-box;
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 6px 8px;
      width: 100%;
      height: calc(1.5rem + 6px * 2);
      border-radius: calc(var(--radius-inherited) - var(--padding-menu-inherited));
      cursor: default;
    }

    .user:hover,
    .user[data-active="true"] {
      background-color: var(--color-hover-inherited);
    }

    .avatar {
      width: 1.5rem;
      height: 1.5rem;
      border-radius: 50%;
      background-color: var(--color-avatar-fallback-inherited);
      overflow: hidden;
      flex-shrink: 0;
    }

    .img {
      display: block;
      width: 100%;
      height: 100%;
    }

    .img:not([src]) { display: none }

    .handle {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
  </style>
`;

const user = document.createElement("template");
user.innerHTML = `
  <li>
    <button class="user" part="user">
      <div class="avatar" part="avatar">
        <img class="img" part="img">
      </div>
      <span class="handle" part="handle"></span>
    </button>
  </li>
`;

/**
 * @template {HTMLElement} T
 * @param {T} tmpl
 */
function clone(tmpl) {
  return /** @type {T} */ (tmpl.cloneNode(true));
}

/**
 * @attribute {string} [host] - The host to which to make the typeahead API call. If set to "location" it uses window.location.
 * @attribute {string} [client] - The optional value to send in the X-Client HTTP header.
 * @attribute {number} [rows] - The maximum number of rows to display in the dropdown.
 *
 * @csspart menu - The dropdown menu.
 * @csspart user - The user row.
 * @csspart avatar - The user avatar wrapper.
 * @csspart img - The user avatar image.
 * @csspart handle - The user handle text.
 *
 * @slot - The <input> tag to progressively enhance.
 *
 * @cssprop --color-background - Controls the color of the dropdown background.
 * @cssprop --color-border - Controls the color of the dropdown border.
 * @cssprop --color-shadow - Controls the color of the dropdown shadow.
 * @cssprop --color-hover - Controls the background color of each row on hover.
 * @cssprop --color-avatar-fallback - Controls the background color of an avatar circle if the image fails to load.
 * @cssprop --radius - Controls the corner radius of the dropdown.
 * @cssprop --padding-menu - Controls the padding of the dropdown menu.
 *
 * @summary A small web component that progressively enhances an <input> element into an autocomplete for ATProto handles!
 *
 * @tag actor-typeahead
 */
export default class ActorTypeahead extends HTMLElement {
  static tag = "actor-typeahead";

  static define(tag = this.tag) {
    this.tag = tag;

    const name = customElements.getName(this);
    if (name && name !== tag)
      return console.warn(`${this.name} already defined as <${name}>!`);

    const ce = customElements.get(tag);
    if (ce && ce !== this)
      return console.warn(`<${tag}> already defined as ${ce.name}!`);

    customElements.define(tag, this);
  }

  static {
    const tag = new URL(import.meta.url).searchParams.get("tag") || this.tag;
    if (tag !== "none") this.define(tag);
  }

  #shadow = this.attachShadow({ mode: "closed" });

  /** @type {Array<{ handle: string; avatar: string }>} */
  #actors = [];
  #index = -1;
  /** @type {HTMLInputElement} */
  #input;
  /** @type {number | undefined} */
  #oninputTimeoutId = undefined;
  #pressed = false;
  /** @type {AbortController | undefined} */
  #controller = undefined;

  constructor() {
    super();

    this.#shadow.append(clone(template).content);
    this.#render();
    this.addEventListener("input", this);
    this.addEventListener("focusout", this);
    this.addEventListener("keydown", this);
    this.#shadow.addEventListener("pointerdown", this);
    this.#shadow.addEventListener("pointerup", this);
    this.#shadow.addEventListener("click", this);
    this.#input = this.querySelector("input");
    if (!this.#input) {
      console.error(`Missing <input> tag inside <${ActorTypeahead.tag}>`);
    }
    this.#input.autocomplete = "off";
  }

  get #rows() {
    const rows = Number.parseInt(this.getAttribute("rows") ?? "");

    if (Number.isNaN(rows)) return 5;
    return rows;
  }

  /** @type {string} */
  get #host() {
    const host = this.getAttribute("host");
    return host === "location"
      ? window.location
      : host || "https://public.api.bsky.app";
  }

  /** @param {Event} evt */
  handleEvent(evt) {
    switch (evt.type) {
      case "input":
        this.#oninput(
          /** @type {InputEvent & { target: HTMLInputElement }} */ (evt),
        );
        break;

      case "keydown":
        this.#onkeydown(/** @type {KeyboardEvent} */ (evt));
        break;

      case "focusout":
        this.#onfocusout(evt);
        break;

      case "pointerdown":
        this.#onpointerdown(
          /** @type {PointerEvent & { target: HTMLElement }} */ (evt),
        );
        break;

      case "pointerup":
        this.#onpointerup(
          /** @type {PointerEvent & { target: HTMLElement }} */ (evt),
        );
        break;
    }
  }

  /** @param {KeyboardEvent} evt */
  #onkeydown(evt) {
    switch (evt.key) {
      case "ArrowDown":
        evt.preventDefault();
        if (this.#actors.length === 0) {
          this.#oninput(evt);
          break;
        }
        this.#index = Math.min(this.#index + 1, this.#actors.length - 1);
        this.#render();
        break;

      case "PageDown":
        evt.preventDefault();
        this.#index = this.#actors.length - 1;
        this.#render();
        break;

      case "ArrowUp":
        evt.preventDefault();
        this.#index = Math.max(this.#index - 1, 0);
        this.#render();
        break;

      case "PageUp":
        evt.preventDefault();
        this.#index = 0;
        this.#render();
        break;

      case "Escape":
        evt.preventDefault();
        this.#actors = [];
        this.#index = -1;
        this.#render();
        break;

      case "Enter":
        const selected = this.#shadow.querySelectorAll("button")[this.#index];
        if (selected) {
          evt.preventDefault();
          selected.dispatchEvent(
            new PointerEvent("pointerup", { bubbles: true }),
          );
        }
        break;
    }
  }

  /** @param {InputEvent & { target: HTMLInputElement }} evt */
  #oninput(evt) {
    clearTimeout(this.#oninputTimeoutId);
    this.#oninputTimeoutId = setTimeout(
      this.#oninputDebounced.bind(this),
      250,
      evt,
    );
  }

  /** @param {InputEvent & { target: HTMLInputElement }} evt */
  async #oninputDebounced(evt) {
    const query = evt.target?.value;
    if (!query) {
      this.#actors = [];
      this.#render();
      return;
    }

    const url = new URL(
      "xrpc/app.bsky.actor.searchActorsTypeahead",
      this.#host,
    );
    url.searchParams.set("q", query);
    url.searchParams.set("limit", `${this.#rows}`);

    this.#controller?.abort();
    this.#controller = new AbortController();

    const headers = {};
    const client = this.getAttribute("client");
    if (client) {
      headers["X-Client"] = client;
    }

    try {
      const res = await fetch(url, {
        headers,
        signal: this.#controller.signal,
      });
      const json = await res.json();
      this.#actors = json.actors;
      this.#index = -1;
      this.#render();
    } catch {}
  }

  /** @param {Event} evt */
  async #onfocusout(evt) {
    if (this.#pressed) return;

    this.#actors = [];
    this.#index = -1;
    this.#render();
  }

  #render() {
    const fragment = document.createDocumentFragment();
    let i = -1;
    for (const actor of this.#actors) {
      const li = clone(user).content;

      const button = li.querySelector("button");
      if (button) {
        button.dataset.handle = actor.handle;
        if (++i === this.#index) button.dataset.active = "true";
      }

      const avatar = li.querySelector("img");
      if (avatar && actor.avatar) avatar.src = actor.avatar;

      const handle = li.querySelector(".handle");
      if (handle) handle.textContent = actor.handle;

      fragment.append(li);
    }

    this.#shadow.querySelector(".menu")?.replaceChildren(...fragment.children);
  }

  /** @param {PointerEvent} evt */
  #onpointerdown(evt) {
    this.#pressed = true;
  }

  /** @param {PointerEvent & { target: HTMLElement }} evt */
  #onpointerup(evt) {
    this.#pressed = false;

    this.#input.focus();

    const button = evt.target?.closest("button");
    if (!button) return;

    this.#input.value = button.dataset.handle || "";
    this.#actors = [];
    this.#render();
  }
}
