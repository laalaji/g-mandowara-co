/* G Mandowara & Co. — secure form handler (contact + career)
   - Fetches a fresh CSRF + math-captcha token from /api/form-init
   - Honeypot + client-side validation before submit
   - Submits via fetch to /api/contact or /api/career
   No inline handlers, no eval. */
(function () {
  'use strict';

  var contactForm = document.getElementById('contactForm');
  var careerForm = document.getElementById('careerForm');
  var form = contactForm || careerForm;
  if (!form) return;

  var endpoint = contactForm ? 'api/contact' : 'api/career';
  var msgEl = document.getElementById('formMsg');
  var captchaQ = document.getElementById('captchaQ');
  var csrfEl = form.querySelector('[name="csrf_token"]');
  var captchaIdEl = form.querySelector('[name="captcha_id"]');
  var submitBtn = form.querySelector('button[type="submit"]');

  function showMessage(type, text) {
    if (!msgEl) return;
    msgEl.textContent = text;
    msgEl.className = 'form-message show ' + type;
    msgEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function clearMessage() {
    if (!msgEl) return;
    msgEl.className = 'form-message';
    msgEl.textContent = '';
  }

  // --- Load CSRF + captcha token ---
  function initToken() {
    fetch('api/form-init', { method: 'GET', credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { if (!r.ok) throw new Error('init ' + r.status); return r.json(); })
      .then(function (d) {
        if (csrfEl) csrfEl.value = d.csrf_token || '';
        if (captchaIdEl) captchaIdEl.value = d.captcha_id || '';
        if (captchaQ) captchaQ.textContent = d.captcha_question ? (d.captcha_question + ' =') : 'Captcha unavailable';
      })
      .catch(function () {
        if (captchaQ) captchaQ.textContent = 'Captcha unavailable — try refresh';
      });
  }
  initToken();

  // --- Career: file dropzone UX ---
  var fileInput = document.getElementById('cv-file');
  var dropzone = document.getElementById('dropzone');
  var dzFilename = document.getElementById('dzFilename');
  var MAX_BYTES = 5 * 1024 * 1024;
  var ALLOWED_EXT = ['pdf', 'doc', 'docx'];

  function describeFile(file) {
    if (!file) return;
    var ext = (file.name.split('.').pop() || '').toLowerCase();
    if (ALLOWED_EXT.indexOf(ext) === -1) {
      showMessage('error', 'Please upload a PDF, DOC, or DOCX file.');
      fileInput.value = '';
      if (dzFilename) { dzFilename.hidden = true; dzFilename.textContent = ''; }
      return;
    }
    if (file.size > MAX_BYTES) {
      showMessage('error', 'File is too large. Maximum size is 5 MB.');
      fileInput.value = '';
      if (dzFilename) { dzFilename.hidden = true; dzFilename.textContent = ''; }
      return;
    }
    clearMessage();
    if (dzFilename) {
      dzFilename.hidden = false;
      dzFilename.textContent = 'Selected: ' + file.name + ' (' + Math.round(file.size / 1024) + ' KB)';
    }
  }

  if (fileInput) {
    fileInput.addEventListener('change', function () { describeFile(fileInput.files[0]); });
  }
  if (dropzone && fileInput) {
    ['dragenter', 'dragover'].forEach(function (ev) {
      dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.add('dragover'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      dropzone.addEventListener(ev, function (e) { e.preventDefault(); dropzone.classList.remove('dragover'); });
    });
    dropzone.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        fileInput.files = e.dataTransfer.files;
        describeFile(fileInput.files[0]);
      }
    });
  }

  // --- Submit ---
  form.addEventListener('submit', function (e) {
    e.preventDefault();
    clearMessage();

    if (!form.checkValidity()) {
      showMessage('error', 'Please fill in all required fields correctly.');
      form.reportValidity();
      return;
    }

    var fd = new FormData(form);

    // Honeypot client-side short-circuit
    if ((fd.get('company') || '').toString().trim() !== '') {
      showMessage('error', 'Submission blocked.');
      return;
    }

    submitBtn.setAttribute('aria-busy', 'true');
    submitBtn.disabled = true;
    var originalText = submitBtn.textContent;
    submitBtn.textContent = 'Sending…';

    fetch(endpoint, { method: 'POST', body: fd, credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, status: r.status, data: d }; }); })
      .then(function (res) {
        if (res.ok && res.data && res.data.ok) {
          showMessage('success', res.data.message || 'Thank you! Your message has been received.');
          form.reset();
          if (dzFilename) { dzFilename.hidden = true; dzFilename.textContent = ''; }
          initToken(); // fresh token for any further submit
        } else {
          showMessage('error', (res.data && res.data.error) || 'Something went wrong. Please try again.');
          initToken(); // captcha is single-use; refresh it
        }
      })
      .catch(function () {
        showMessage('error', 'Network error. Please check your connection and try again.');
        initToken();
      })
      .finally(function () {
        submitBtn.removeAttribute('aria-busy');
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
      });
  });
})();
