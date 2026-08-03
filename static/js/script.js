const root = document.documentElement;
const storageKey = "phishguard-theme";

function applyTheme(theme) {
    root.setAttribute("data-theme", theme);
}

function initialiseTheme() {
    const saved = window.localStorage.getItem(storageKey);
    applyTheme(saved || "dark");
}

function initialiseThemeToggle() {
    const toggle = document.querySelector("[data-theme-toggle]");
    if (!toggle) return;

    toggle.addEventListener("click", () => {
        const nextTheme = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
        applyTheme(nextTheme);
        window.localStorage.setItem(storageKey, nextTheme);
    });
}

function initialiseExamples() {
    const input = document.querySelector("#url");
    const chips = document.querySelectorAll("[data-example-url]");
    if (!input || !chips.length) return;

    chips.forEach((chip) => {
        chip.addEventListener("click", () => {
            input.value = chip.dataset.exampleUrl || "";
            input.focus();
        });
    });
}

function initialiseLoadingState() {
    const form = document.querySelector("[data-analyze-form]");
    const button = document.querySelector("[data-submit-button]");
    if (!form || !button) return;

    form.addEventListener("submit", () => {
        button.classList.add("is-loading");
        button.setAttribute("disabled", "disabled");
    });
}

function initialiseCopyResult() {
    const button = document.querySelector("[data-copy-result]");
    if (!button) return;

    button.addEventListener("click", async () => {
        const text = button.dataset.copyText || "";
        try {
            await navigator.clipboard.writeText(text);
            const previous = button.textContent;
            button.textContent = "Copied";
            window.setTimeout(() => {
                button.textContent = previous;
            }, 1600);
        } catch (error) {
            button.textContent = "Copy failed";
        }
    });
}

document.addEventListener("DOMContentLoaded", () => {
    initialiseTheme();
    initialiseThemeToggle();
    initialiseExamples();
    initialiseLoadingState();
    initialiseCopyResult();
});
