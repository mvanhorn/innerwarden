# Feature Specification: Dashboard Operator UX and QA Reliability

**Feature Branch**: `017-dashboard-operator-ux`  
**Created**: 2026-04-11  
**Status**: Draft  
**Origin**: Originally authored as `001-dashboard-operator-ux` in the monorepo-level `_innerwarden/specs/` directory on 2026-04-11. Moved into `innerwarden/.specify/features/` the same day and renamed to the `017-` slot to avoid collision with the pre-existing `001-telegram-interactive-triage` feature. **Internal feature lineage is 001; operational slot in this repo is 017.** All internal references (per-page specs under `pages/`, commit messages, the git branch, the `CLAUDE.md` features table) use `017-dashboard-operator-ux` to match the on-disk path.  
**Input**: User description: "Revisao QA inicial e UX profunda do dashboard para dois perfis de operador (esposa foco Home/Threats/Health/Intel e marido tecnico eventual), priorizando nao assustar sem gravidade, nao deixar usuario perdido e corrigir inconsistencias de estado e entendimento operacional"

## User Scenarios & Testing *(mandatory)*


### User Story 1 - Operadora entende risco atual sem se assustar (Priority: P1)

Como operadora principal (esposa), eu quero abrir a Home e entender em poucos segundos o que esta acontecendo, o que ja foi tratado e o que precisa da minha atencao, para manter o controle sem entrar em panico.

**Why this priority**: Esta e a jornada mais frequente e mais critica para operacao diaria. Se falhar, a usuaria perde confianca e pode ignorar risco real ou reagir exageradamente.

**Independent Test**: Pode ser testada integralmente apenas na Home com dados reais e simulados, validando leitura do estado, proximos passos e tom da mensagem.

**Acceptance Scenarios**:

1. **Given** que existem ameacas abertas de severidade alta ou critica, **When** a usuaria abre a Home, **Then** ela ve um resumo claro de risco atual, acao recomendada e prioridade sem contradicoes entre contador, banner e lista recente.
2. **Given** que nao existem ameacas graves ativas, **When** a usuaria abre a Home, **Then** a interface usa tom informativo (nao alarmista), explicando que o sistema esta monitorando e o que foi contido.
3. **Given** dados de alta variacao temporal, **When** a usuaria consulta os KPIs, **Then** cada numero exibe contexto de janela temporal para evitar interpretacao errada.

---

### User Story 2 - Operadora navega para investigacao sem se perder (Priority: P1)

Como operadora principal (esposa), eu quero sair de Home para Threats e chegar no detalhe certo com orientacao de proximo passo, para agir com seguranca mesmo sem perfil tecnico profundo.

**Why this priority**: Mesmo com uma Home clara, a jornada quebra se a usuaria nao souber onde clicar ou onde comecar ao entrar em Threats.

**Independent Test**: Pode ser testada com fluxo direto Home -> Review Threats -> Threats -> detalhe de ameaca, sem depender de Health/Intel.

**Acceptance Scenarios**:

1. **Given** que existe pelo menos uma ameaca ativa prioritaria, **When** a usuaria clica em "Review Threats" na Home, **Then** ela chega em Threats com item prioritario selecionado ou claramente destacado para iniciar investigacao.
2. **Given** que a usuaria ja esta no detalhe de ameaca, **When** ela consulta o topo da tela, **Then** ela entende em linguagem simples status atual, nivel de urgencia e acao recomendada.
3. **Given** que a usuaria usa mobile, **When** ela navega entre Home e Threats, **Then** o conteudo critico permanece legivel sem cortar informacao essencial.

---

### User Story 3 - Parceiro tecnico valida diagnostico rapidamente (Priority: P2)

Como operador tecnico eventual (marido), eu quero consultar Health e Intel com profundidade e confianca de que os textos refletem o estado operacional real, para apoiar decisoes sem ruído.

**Why this priority**: O apoio tecnico e ocasional, mas decisivo em momentos de risco alto e em ajustes de confiabilidade.

**Independent Test**: Pode ser testada com navegacao direta em Health e Intel, verificando coerencia entre mensagem exibida e estado operacional.

**Acceptance Scenarios**:

1. **Given** que nao houve acao de bloqueio executada recentemente, **When** o operador consulta Health, **Then** a mensagem principal nao afirma bloqueio ativo em tempo real sem evidencia correspondente.
2. **Given** que Intel possui grande volume de dados, **When** o operador tecnico acessa a aba em desktop ou mobile, **Then** ele consegue interpretar os dados sem erro funcional e com estrutura legivel.
3. **Given** que existe discrepancia de dados entre fontes, **When** o operador tecnico navega pelas telas, **Then** o sistema sinaliza estado possivelmente desatualizado em vez de mostrar informacao contraditoria.

---

### User Story 4 - Qualidade de dados e UX monitoradas continuamente (Priority: P2)

Como equipe de produto e operacao, queremos regras de QA funcional e UX para evitar regressao de consistencia, tom e orientacao ao usuario, para manter confianca ao longo do tempo.

**Why this priority**: Reduz retrabalho e impede regressao em correcoes que ja foram entregues.

**Independent Test**: Pode ser testada por checklist objetiva com criterios de consistencia, navegacao e legibilidade por perfil.

**Acceptance Scenarios**:

1. **Given** uma nova versao do dashboard, **When** a bateria de revisao QA/UX e executada, **Then** inconsistencias criticas entre estado de risco e mensagens sao identificadas antes de considerar a versao pronta.
2. **Given** o perfil da esposa como primario, **When** a revisao de UX e executada, **Then** o fluxo Home/Threats/Health/Intel nao deixa a usuaria perdida e nao usa tom alarmista sem gravidade real.

### Edge Cases

- Contadores e banners divergem durante picos de atualizacao (ex.: Home indica risco resolvido enquanto lista mostra ameacas abertas).
- Nao ha eventos novos, mas o ultimo estado foi grave; a interface precisa evitar alarme residual sem ocultar historico relevante.
- Existem muitas ameacas em pouco tempo; a usuaria precisa ver prioridade e acao em vez de lista caotica.
- Dados de telemetria ficam temporariamente atrasados; o sistema deve comunicar possivel defasagem sem quebrar fluxo.
- Em mobile, tabelas extensas (especialmente Intel) ultrapassam largura da tela e escondem colunas essenciais.
- Operadora abre Threats via CTA e nao encontra detalhe selecionado automaticamente, gerando duvida sobre o proximo passo.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: O dashboard MUST apresentar estado de risco consistente entre Home, Threats, Health e Intel para o mesmo momento de observacao.
- **FR-002**: O dashboard MUST evitar mensagens alarmistas quando nao houver gravidade alta ou critica ativa.
- **FR-003**: O dashboard MUST escalar tom e destaque visual de acordo com gravidade operacional real, com niveis distintos de informativo, atencao e urgente.
- **FR-004**: A Home MUST mostrar um resumo operacional com tres respostas explicitas: o que aconteceu, o que ja foi tratado e o que precisa ser feito agora.
- **FR-005**: A Home MUST oferecer caminho direto para investigacao quando houver pendencias relevantes.
- **FR-006**: O fluxo Home -> Threats MUST levar a operadora para uma lista priorizada e com proximo passo claro.
- **FR-007**: Threats MUST apresentar detalhe de incidente com status atual, contexto minimo e acao recomendada em linguagem compreensivel para operador nao tecnico.
- **FR-008**: Health MUST refletir capacidade de resposta real, evitando afirmar acao automatica sem evidencia operacional correspondente.
- **FR-009**: Intel MUST permanecer funcional em todas as subabas, sem erro de carregamento e sem degradar leitura essencial.
- **FR-010**: Intel em mobile MUST expor dados prioritarios de forma legivel, mesmo quando houver muitas colunas ou grande volume.
- **FR-011**: KPIs de alto impacto MUST exibir janela temporal ou referencia de atualizacao para reduzir interpretacao ambigua.
- **FR-012**: O dashboard MUST indicar quando informacoes estao possivelmente defasadas ou em sincronizacao parcial.
- **FR-013**: A interface MUST preservar acessibilidade basica de navegacao por teclado em elementos interativos principais.
- **FR-014**: O sistema MUST suportar dois perfis de leitura: operador principal (resumo orientado a acao) e operador tecnico (diagnostico detalhado).
- **FR-015**: Cada release MUST ser validada por checklist de QA e UX voltada aos fluxos Home, Threats, Health e Intel.

### Key Entities *(include if feature involves data)*

- **Operator Profile**: Representa tipo de usuario (operadora principal ou suporte tecnico), com necessidade de profundidade e linguagem diferentes.
- **Operational Risk Snapshot**: Estado consolidado do momento, contendo severidade, quantidade de pendencias, tratativas realizadas e nivel de urgencia recomendado.
- **Threat Investigation Context**: Conjunto de informacoes de investigacao exibidas no Threats, incluindo status da ameaca, narrativa curta, proximos passos e evidencias principais.
- **Health Capability State**: Estado operacional das capacidades de protecao e resposta, incluindo disponibilidade, efetividade recente e confiabilidade percebida.
- **Intel View State**: Estado de visualizacao de inteligencia com foco em legibilidade, filtros e acesso a dados prioritarios por dispositivo.
- **UX Guidance Block**: Bloco textual orientado a acao que descreve o que o usuario deve fazer agora sem sobrecarga cognitiva.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Em cenarios com risco ativo, a operadora principal identifica estado atual e proxima acao em ate 30 segundos em 90% dos testes guiados.
- **SC-002**: Inconsistencias criticas entre estado exibido na Home e estado de ameacas abertas sao reduzidas a 0 ocorrencias nos testes de regressao.
- **SC-003**: Em validacao mobile, 100% das informacoes prioritarias de Home, Threats, Health e Intel permanecem legiveis sem perda de entendimento da acao recomendada.
- **SC-004**: Em revisao com usuarios alvo, pelo menos 85% classificam a comunicacao de risco como clara e nao alarmista quando nao ha gravidade critica ativa.
- **SC-005**: O fluxo Home -> Threats permite chegar ao contexto de investigacao inicial em no maximo 2 interacoes em 95% dos cenarios de teste.

## Assumptions

- O servidor e de capacidade basica, portanto mensagens e fluxo devem priorizar clareza e estabilidade de leitura em vez de densidade visual excessiva.
- A esposa e a operadora principal e acessa regularmente Home, Threats, Health e Intel; o marido acessa de forma ocasional para apoio tecnico.
- O projeto mantera os quatro modulos principais como superfice de operacao prioritaria no curto prazo.
- A experiencia deve funcionar em desktop e mobile sem exigir treinamento tecnico formal para a operadora principal.
- A consistencia de estado entre telas e fonte de dados e requisito funcional, nao apenas melhoria estetica.
