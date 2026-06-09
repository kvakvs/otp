/*
 * Enhances ExDoc code blocks annotated with:
 *
 *   <!-- doctest-context: name -->
 *
 * The context definitions are emitted by make/ex_doc.exs as JSON in
 * #otp-doctest-contexts-data.
 */
(function () {
  const DATA_ID = "otp-doctest-contexts-data";
  const ENHANCED_ATTR = "data-otp-doctest-context-enhanced";
  const warnedComments = new WeakSet();

  function loadContexts() {
    const data = document.getElementById(DATA_ID);
    if (!data) {
      return {};
    }

    try {
      return JSON.parse(data.textContent || "{}");
    } catch (error) {
      console.warn("Failed to parse doctest context definitions.", error);
      return {};
    }
  }

  function nextMeaningfulElement(node) {
    let sibling = node.nextSibling;

    while (sibling) {
      if (sibling.nodeType === Node.ELEMENT_NODE) {
        return sibling;
      }

      if (
        sibling.nodeType === Node.TEXT_NODE &&
        sibling.textContent.trim() !== ""
      ) {
        return null;
      }

      sibling = sibling.nextSibling;
    }

    return null;
  }

  function contextNameFromComment(comment) {
    const match = comment.nodeValue.match(/^\s*doctest-context\s*:\s*(.*?)\s*$/);
    return match ? match[1] : null;
  }

  function codeBlockFromElement(element) {
    if (element.tagName === "PRE") {
      return element;
    }

    return element.querySelector("pre");
  }

  function makeContextBlock(text, kind, sourceCode) {
    const pre = document.createElement("pre");
    const code = document.createElement("code");

    pre.className = "otp-doctest-context-block otp-doctest-context-" + kind;
    pre.hidden = true;

    if (sourceCode) {
      code.className = sourceCode.className;
    }

    code.textContent = text;
    pre.appendChild(code);

    return pre;
  }

  function makeToggleButton() {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "otp-doctest-context-toggle";
    button.setAttribute("aria-expanded", "false");
    button.textContent = "Show context";
    return button;
  }

  function enhanceBlock(pre, context) {
    const code = pre.querySelector("code");
    const prolog = context.prolog || "";
    const epilog = context.epilog || "";

    if (!code || (!prolog && !epilog)) {
      return;
    }

    pre.setAttribute(ENHANCED_ATTR, "true");
    pre.classList.add("otp-doctest-context-main");

    const controls = document.createElement("div");
    controls.className = "otp-doctest-context-controls";

    const button = makeToggleButton();
    controls.appendChild(button);

    const blocks = [];
    pre.parentNode.insertBefore(controls, pre);

    if (prolog) {
      const prologBlock = makeContextBlock(prolog, "prolog", code);
      pre.parentNode.insertBefore(prologBlock, pre);
      blocks.push(prologBlock);
    }

    if (epilog) {
      const epilogBlock = makeContextBlock(epilog, "epilog", code);
      pre.insertAdjacentElement("afterend", epilogBlock);
      blocks.push(epilogBlock);
    }

    button.addEventListener("click", () => {
      const expanded = button.getAttribute("aria-expanded") === "true";
      const nextExpanded = !expanded;

      button.setAttribute("aria-expanded", String(nextExpanded));
      button.textContent = nextExpanded ? "Hide context" : "Show context";

      for (const block of blocks) {
        block.hidden = !nextExpanded;
      }
    });
  }

  function enhanceDoctestContexts() {
    const contexts = loadContexts();
    const root = document.querySelector(".content-inner") || document.body;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_COMMENT);

    while (walker.nextNode()) {
      const comment = walker.currentNode;
      const name = contextNameFromComment(comment);

      if (!name) {
        continue;
      }

      const element = nextMeaningfulElement(comment);
      const pre = element ? codeBlockFromElement(element) : null;

      if (!pre || pre.tagName !== "PRE" || pre.hasAttribute(ENHANCED_ATTR)) {
        continue;
      }

      if (!Object.prototype.hasOwnProperty.call(contexts, name)) {
        if (!warnedComments.has(comment)) {
          warnedComments.add(comment);
          console.warn("Unknown doctest context: " + name);
        }

        continue;
      }

      enhanceBlock(pre, contexts[name]);
    }
  }

  window.addEventListener("exdoc:loaded", enhanceDoctestContexts);

  if (document.readyState !== "loading") {
    enhanceDoctestContexts();
  }
})();
