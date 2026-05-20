/* G Mandowara & Co. — Front-end interactions
   No external state, no inline event handlers, no eval. */
(function () {
  'use strict';

  /* ---------- Mobile nav toggle ---------- */
  var toggle = document.getElementById('navToggle');
  var nav = document.getElementById('primaryNav');
  if (toggle && nav) {
    toggle.addEventListener('click', function () {
      var open = toggle.getAttribute('aria-expanded') === 'true';
      toggle.setAttribute('aria-expanded', String(!open));
      nav.classList.toggle('open');
    });

    document.addEventListener('click', function (e) {
      if (!nav.contains(e.target) && !toggle.contains(e.target) && nav.classList.contains('open')) {
        nav.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      }
    });

    var links = nav.querySelectorAll('a');
    for (var i = 0; i < links.length; i++) {
      links[i].addEventListener('click', function () {
        if (window.innerWidth < 901) {
          nav.classList.remove('open');
          toggle.setAttribute('aria-expanded', 'false');
        }
      });
    }
  }

  /* ---------- Sticky header shadow (rAF-throttled) ---------- */
  var header = document.getElementById('siteHeader');
  if (header) {
    var ticking = false;
    var lastState = false;
    var onScroll = function () {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(function () {
        var scrolled = window.scrollY > 12;
        if (scrolled !== lastState) {
          header.classList.toggle('is-scrolled', scrolled);
          lastState = scrolled;
        }
        ticking = false;
      });
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  /* ---------- Year in footer ---------- */
  var year = document.getElementById('year');
  if (year) year.textContent = String(new Date().getFullYear());

  /* ---------- Init AOS if present, fall back to local reveal ---------- */
  if (typeof window.AOS !== 'undefined' && typeof window.AOS.init === 'function') {
    window.AOS.init({
      duration: 800,
      easing: 'ease-out-cubic',
      once: true,
      offset: 60,
      disable: function () { return window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
    });
    // Safety net: if any [data-aos] is still hidden after a generous delay
    // (e.g., AOS observer missed it, slow CDN, JS error), force-reveal it
    // so content is never trapped at opacity:0.
    setTimeout(function () {
      var hidden = document.querySelectorAll('[data-aos]:not(.aos-animate)');
      for (var n = 0; n < hidden.length; n++) hidden[n].classList.add('aos-animate');
    }, 2500);
  } else {
    // AOS failed to load (CDN blocked) — make sure data-aos elements aren't invisible
    var stuck = document.querySelectorAll('[data-aos]');
    for (var m = 0; m < stuck.length; m++) stuck[m].style.opacity = '1';
  }
  if (typeof window.AOS === 'undefined') {
    var els = document.querySelectorAll('.reveal');
    if ('IntersectionObserver' in window && els.length) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
          if (e.isIntersecting) {
            e.target.classList.add('is-visible');
            io.unobserve(e.target);
          }
        });
      }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
      for (var j = 0; j < els.length; j++) io.observe(els[j]);
    } else {
      for (var k = 0; k < els.length; k++) els[k].classList.add('is-visible');
    }
  }

  /* ---------- Animated counters ---------- */
  var counters = document.querySelectorAll('[data-count]');
  if (counters.length && 'IntersectionObserver' in window) {
    var io2 = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) {
          var el = e.target;
          var target = parseInt(el.getAttribute('data-count'), 10);
          if (!isNaN(target)) animateCount(el, target);
          io2.unobserve(el);
        }
      });
    }, { threshold: 0.5 });
    for (var c = 0; c < counters.length; c++) io2.observe(counters[c]);
  }

  function animateCount(el, target) {
    var raw = el.textContent || '';
    var suffixMatch = raw.match(/[^\d]+$/);
    var suffix = suffixMatch ? suffixMatch[0] : '';
    var duration = 1600;
    var start = performance.now();
    function step(now) {
      var t = Math.min(1, (now - start) / duration);
      var eased = 1 - Math.pow(1 - t, 3);
      var val = Math.round(target * eased);
      el.textContent = val + suffix;
      if (t < 1) requestAnimationFrame(step);
    }
    requestAnimationFrame(step);
  }

})();
