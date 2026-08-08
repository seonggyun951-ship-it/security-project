// 조회/처리 실패를 화면에 드러내는 배너.
// 없으면 실패가 "데이터 없음"처럼 보여서 사용자도 개발자도 원인을 모른다.
export default function ErrorBanner({ message, onRetry }) {
  if (!message) return null
  return (
    <div className="ac-error-banner" role="alert">
      <span className="ac-error-banner-text">{message}</span>
      {onRetry && (
        <button className="ac-btn ac-btn-secondary ac-error-banner-btn" onClick={onRetry}>
          다시 시도
        </button>
      )}
    </div>
  )
}
