document.addEventListener("DOMContentLoaded", () => {
    const toggle = document.getElementById("burger-toggle");
    const nav = document.getElementById("main-nav");

    if (!toggle || !nav) return;

    toggle.addEventListener("click", () => {
        const isOpen = nav.classList.toggle("nav-open");
        toggle.setAttribute("aria-expanded", isOpen.toString());
    });

    document.addEventListener("click", (e) => {
        if (!nav.contains(e.target)) {
            nav.classList.remove("nav-open");
            toggle.setAttribute("aria-expanded", "false");
        }
    });
});
