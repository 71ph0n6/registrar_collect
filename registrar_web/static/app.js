const urlInput = document.getElementById('urlInput');
const urlCount = document.getElementById('urlCount');
const checkBtn = document.getElementById('checkBtn');
const clearBtn = document.getElementById('clearBtn');
const results = document.getElementById('results');
const groupTemplate = document.getElementById('groupTemplate');
const messageBox = document.getElementById('messageBox');
const summary = document.getElementById('summary');
const totalCount = document.getElementById('totalCount');
const registrarCount = document.getElementById('registrarCount');
const unknownCount = document.getElementById('unknownCount');
const statusPill = document.getElementById('statusPill');

function getLines() {
  return urlInput.value
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(Boolean);
}

function refreshCount() {
  urlCount.textContent = getLines().length;
}

function setMessage(text, type = 'error') {
  messageBox.textContent = text;
  messageBox.className = `message-box ${type}`;
}

function clearMessage() {
  messageBox.textContent = '';
  messageBox.className = 'message-box hidden';
}

async function copyText(text, button, successText) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = successText;
    setTimeout(() => { button.textContent = old; }, 1200);
  } catch {
    alert('Không thể copy tự động. Hãy copy thủ công.');
  }
}

function render(data) {
  results.innerHTML = '';
  summary.classList.remove('hidden');

  totalCount.textContent = data.total;
  registrarCount.textContent = data.groups.filter(g => g.registrar !== 'Unknown').length;
  const unknown = data.groups.find(g => g.registrar === 'Unknown');
  unknownCount.textContent = unknown ? unknown.count : 0;

  for (const group of data.groups) {
    const node = groupTemplate.content.cloneNode(true);
    const card = node.querySelector('.registrar-card');
    const name = node.querySelector('.registrar-name');
    const countBadge = node.querySelector('.count-badge');
    const emailLink = node.querySelector('.abuse-email');
    const copyEmailBtn = node.querySelector('.copy-email-btn');
    const copyUrlsBtn = node.querySelector('.copy-urls-btn');
    const urlList = node.querySelector('.url-list');

    name.textContent = group.registrar;
    countBadge.textContent = `${group.count} URL`;
    emailLink.textContent = group.abuse_email;

    if (group.abuse_email !== 'Unknown') {
      emailLink.href = `mailto:${group.abuse_email}`;
      copyEmailBtn.addEventListener('click', () =>
        copyText(group.abuse_email, copyEmailBtn, 'Đã copy')
      );
    } else {
      emailLink.removeAttribute('href');
      copyEmailBtn.disabled = true;
      copyEmailBtn.textContent = 'No email';
    }

    copyUrlsBtn.addEventListener('click', () =>
      copyText(group.urls.join('\n'), copyUrlsBtn, 'Đã copy')
    );

    for (const url of group.urls) {
      const div = document.createElement('div');
      div.className = 'url-item';
      div.textContent = url;
      urlList.appendChild(div);
    }

    if (group.registrar === 'Unknown') {
      card.dataset.unknown = 'true';
    }

    results.appendChild(node);
  }
}

urlInput.addEventListener('input', refreshCount);

clearBtn.addEventListener('click', () => {
  urlInput.value = '';
  results.innerHTML = '';
  summary.classList.add('hidden');
  clearMessage();
  refreshCount();
  statusPill.textContent = 'Sẵn sàng';
  urlInput.focus();
});

checkBtn.addEventListener('click', async () => {
  clearMessage();
  results.innerHTML = '';
  summary.classList.add('hidden');

  const urls = getLines();
  if (!urls.length) {
    setMessage('Hãy dán ít nhất một URL.');
    return;
  }

  checkBtn.disabled = true;
  checkBtn.textContent = 'Đang kiểm tra...';
  statusPill.textContent = `Đang xử lý ${urls.length} URL`;

  try {
    const response = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ urls: urlInput.value })
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Có lỗi xảy ra.');
    }

    render(data);
    setMessage(`Hoàn tất ${data.total} URL.`, 'success');
    statusPill.textContent = 'Hoàn tất';
  } catch (error) {
    setMessage(error.message || 'Không thể kết nối tới server.');
    statusPill.textContent = 'Có lỗi';
  } finally {
    checkBtn.disabled = false;
    checkBtn.textContent = 'Kiểm tra Registrar';
  }
});

refreshCount();
