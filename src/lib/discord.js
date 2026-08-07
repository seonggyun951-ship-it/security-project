const WEBHOOK_URL = 'https://discordapp.com/api/webhooks/1535279854721966153/Qb6htpTyiTN1QcI0-QBlf2v92C9X7qKuYSSsuIYf8D6lZNq_Ez3r_78n39fD0eix-Dny'

export async function notify(message) {
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: message }),
    })
  } catch (_) {
    // 알림 실패해도 본 기능에 영향 없도록
  }
}
