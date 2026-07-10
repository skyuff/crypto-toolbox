const b64 = $b64;
const byteChars = atob(b64);
const bytes = new Uint8Array(byteChars.length);
for (let i = 0; i < byteChars.length; i++) bytes[i] = byteChars.charCodeAt(i);
const file = new File([bytes], 'baolei_first_50.pcapng', { type: 'application/octet-stream' });
const input = document.querySelector('input[type=file]');
if (input) {
  const dt = new DataTransfer();
  dt.items.add(file);
  input.files = dt.files;
  input.dispatchEvent(new Event('change', { bubbles: true }));
  console.log('injected', file.name, file.size);
} else {
  console.log('no file input');
}