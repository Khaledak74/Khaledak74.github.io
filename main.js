/* ============================================
   MOTAW3 PORTFOLIO - MAIN SCRIPTS
   ============================================ */

document.addEventListener('DOMContentLoaded', function() {
    // --- Navbar scroll effect ---
    const navbar = document.querySelector('.navbar');

    function handleScroll() {
        if (window.scrollY > 10) {
            navbar.classList.add('scrolled');
        } else {
            navbar.classList.remove('scrolled');
        }
    }

    window.addEventListener('scroll', handleScroll);
    handleScroll(); // Check on load

    // --- Mobile menu toggle ---
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav-links');

    if (hamburger && navLinks) {
        hamburger.addEventListener('click', function() {
            navLinks.classList.toggle('active');

            // Animate hamburger to X
            const spans = hamburger.querySelectorAll('span');
            if (navLinks.classList.contains('active')) {
                spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
                spans[1].style.opacity = '0';
                spans[2].style.transform = 'rotate(-45deg) translate(5px, -5px)';
            } else {
                spans[0].style.transform = 'none';
                spans[1].style.opacity = '1';
                spans[2].style.transform = 'none';
            }
        });

        // Close menu when clicking a link
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.classList.remove('active');
                const spans = hamburger.querySelectorAll('span');
                spans[0].style.transform = 'none';
                spans[1].style.opacity = '1';
                spans[2].style.transform = 'none';
            });
        });
    }

    // --- Active nav link highlighting ---
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    document.querySelectorAll('.nav-links a').forEach(link => {
        const linkPage = link.getAttribute('href');
        if (linkPage === currentPage || (currentPage === '' && linkPage === 'index.html')) {
            link.classList.add('active');
        }
    });

    // --- Smooth reveal on scroll ---
    const revealElements = document.querySelectorAll('.card, .blog-item, .skill-item, .cert-card, .contact-method, .contact-card');

    const revealObserver = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, { threshold: 0.1 });

    revealElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
        revealObserver.observe(el);
    });

    // --- Typing effect for hero (optional) ---
    const heroTitle = document.querySelector('.hero h1');
    if (heroTitle && !sessionStorage.getItem('heroAnimated')) {
        const text = heroTitle.textContent;
        heroTitle.textContent = '';
        let i = 0;

        function typeWriter() {
            if (i < text.length) {
                heroTitle.textContent += text.charAt(i);
                i++;
                setTimeout(typeWriter, 80);
            }
        }

        setTimeout(typeWriter, 300);
        sessionStorage.setItem('heroAnimated', 'true');
    }

    // --- Console easter egg ---
    console.log('%c🔒 SOC Analyst Portfolio', 'color: #39d0d8; font-size: 20px; font-weight: bold;');
    console.log('%cBuilt with curiosity & caffeine', 'color: #8b949e; font-size: 12px;');
});
/* --- Page transition (montage-style artwork overlay) ---
   Internal navigation: artwork fades in with a slight zoom, then the new page
   loads and the artwork fades out. Skipped entirely for reduced-motion users
   and never plays on first load. */
(function () {
    var KEY = 'm3-transition';
    var reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function buildOverlay() {
        var o = document.createElement('div');
        o.className = 'page-transition';
        o.setAttribute('aria-hidden', 'true');
        o.innerHTML = '<img class="pt-art" src="assets/transition-luffy.webp" alt="">' +
                      '<span class="pt-mark"><span class="pt-gt">&gt;</span>M3</span>';
        document.body.appendChild(o);
        return o;
    }

    // Warm the cache for the next navigation.
    var warm = new Image();
    warm.src = 'assets/transition-luffy.webp';

    if (reduced) { sessionStorage.removeItem(KEY); return; }

    // Arrival: if we navigated here through the transition, fade the artwork out.
    if (sessionStorage.getItem(KEY) === '1') {
        sessionStorage.removeItem(KEY);
        var ov = buildOverlay();
        ov.classList.add('pt-active');
        requestAnimationFrame(function () {
            requestAnimationFrame(function () {
                ov.classList.remove('pt-active');
                ov.classList.add('pt-leaving');
                setTimeout(function () { ov.remove(); }, 380);
            });
        });
    }

    // Departure: intercept same-origin page links.
    document.addEventListener('click', function (e) {
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        var a = e.target.closest ? e.target.closest('a[href]') : null;
        if (!a || a.target === '_blank' || a.hasAttribute('download')) return;
        var href = a.getAttribute('href');
        if (!href || href.charAt(0) === '#' || /^(https?:|mailto:|tel:)/i.test(href)) {
            if (href && /^(https?:)/i.test(href)) {
                try {
                    var u = new URL(href, location.href);
                    if (u.origin !== location.origin) return;
                    if (u.pathname === location.pathname) return;
                } catch (err) { return; }
            } else {
                return;
            }
        }
        var dest = href;
        e.preventDefault();
        sessionStorage.setItem(KEY, '1');
        var ov2 = document.querySelector('.page-transition') || buildOverlay();
        ov2.classList.remove('pt-leaving');
        void ov2.offsetWidth;
        ov2.classList.add('pt-active');
        setTimeout(function () { location.href = dest; }, 420);
    });
})();
