async function sendViaResend({ to, subject, text }) {
  const apiKey = process.env.RESEND_API_KEY;
  const from = process.env.RESEND_FROM || 'Filter <onboarding@resend.dev>';
  if (!apiKey) {
    console.log(`[email:console] to=${to.join(',')} subject="${subject}"\n${text}\n`);
    return;
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ from, to, subject, text }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    console.error(`[email:resend] failed ${res.status} ${body}`);
  }
}

export async function notifyAdminOfRequest({ admin, user, domain, reason }) {
  if (!admin?.email) return;
  const subject = `Access request: ${user.name} → ${domain}`;
  const text = [
    `${user.name} (${user.email}) requested access to ${domain}.`,
    '',
    'Reason:',
    reason,
    '',
    'Review it in the admin dashboard.',
  ].join('\n');
  await sendViaResend({ to: [admin.email], subject, text });
}
