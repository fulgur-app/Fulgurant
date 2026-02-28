document.addEventListener("DOMContentLoaded", () => {
    const csrfTokenElement = document.querySelector('meta[name="csrf-token"]');
    if (!csrfTokenElement) {
        return;
    }

    document.body.addEventListener("htmx:configRequest", (event) => {
        event.detail.headers["x-csrf-token"] = csrfTokenElement.getAttribute("content");
    });
});
