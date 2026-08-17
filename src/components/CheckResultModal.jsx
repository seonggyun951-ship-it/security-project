import ExplainPanel from './ExplainPanel'

// 신청 접수 전 점검 결과를 보여준다.
//
// 예전에는 alert/confirm으로 띄웠는데, 규칙 엔진이 내놓은 문장을 그대로 나열할 뿐이라
// 신청자가 "그래서 뭘 어떻게 고치라는 건지" 알기 어려웠다. 여기서는 사유를 보여주고,
// 더 알고 싶으면 설명을 만들어 볼 수 있게 한다.
//
// 설명을 미리 만들어두지 않는 이유는 몇 초가 걸리기 때문이다. 신청 버튼을 누르고
// 그만큼 기다리게 하면 점검이 방해물처럼 느껴진다.
export default function CheckResultModal({ mode, findings, request, onCancel, onProceed }) {
  const blocked = mode === 'blocked'
  const shown = findings.filter((f) => f.severity === (blocked ? 'high' : 'medium'))

  return (
    <div className="ac-datepop-backdrop" onClick={onCancel}>
      <div className="ac-datepop cm" onClick={(e) => e.stopPropagation()}>
        <div className="cm-head">
          <span className={`cm-tag ${blocked ? 'cm-tag-block' : 'cm-tag-warn'}`}>
            {blocked ? '위험' : '주의'}
          </span>
          <span className="cm-title">
            {blocked ? '이 내용은 신청할 수 없습니다' : '관리자가 직접 확인하는 항목입니다'}
          </span>
        </div>

        <div className="cm-list">
          {shown.map((f, i) => (
            <div key={i} className="cm-item">
              <div className="cm-item-title">{f.title}</div>
              {f.why && <div className="cm-item-why">{f.why}</div>}
            </div>
          ))}
        </div>

        <ExplainPanel request={request} />

        <div className="ac-datepop-actions cm-actions">
          {blocked ? (
            <button className="ac-btn" onClick={onCancel}>수정하러 가기</button>
          ) : (
            <>
              <button className="ac-btn" onClick={onProceed}>신청</button>
              <button className="ac-btn ac-btn-secondary" onClick={onCancel}>취소</button>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
