<p align="center">
  <img src="docs/assets/banner.svg" alt="bountyproof: el agente de bug bounty que no reporta lo que no puede probar" width="100%">
</p>

> Versión en español. La documentación de referencia está en inglés: [README.md](README.md).

**bountyproof** es un harness de agentes para bug bounty construido sobre Claude Code. Divide cada
engagement en fases que ejecutan agentes distintos, mantiene cada petición dentro del scope del programa
con un hook y pone un juez de evidencias independiente delante de cada informe. Un hallazgo es falso
hasta que el juez ve el artefacto que distingue "vulnerable" de "benigno".

## Por qué

Los programas de bug bounty están saturados de informes generados con IA que no aguantan la primera
reproducción. curl cerró su bug bounty de pago en enero de 2026 por esa avalancha
([BleepingComputer][curl]). La mayoría de herramientas de IA buscan encontrar más. bountyproof busca que
te crean:

- **Descubrir y validar son agentes distintos.** El agente que propone un bug nunca lo confirma.
- **Un juez de evidencias filtra cada informe.** Condiciones de explotación, la mejor explicación
  benigna y el artefacto que discrimina. Si falta algo, no hay informe.
- **El scope se impone con código, no con el prompt.** Un hook `PreToolUse` bloquea hosts fuera de
  scope, peticiones sin las cabeceras del programa y hosts desconocidos, y registra cada petición.
- **El humano pulsa enviar.** El agente redacta y revisa; nunca envía un informe.

## Empezar

Dentro de Claude Code:

```text
/plugin marketplace add jorge-asenjo/bountyproof
/plugin install bountyproof@bountyproof
/bountyproof:new "Acme Corp" --platform hackerone --mode blackbox
```

Después abre Claude Code en el workspace nuevo y ejecuta `/bountyproof:setup <URL del programa>`.

¿Primera vez? `bountyproof onboard` revisa tu máquina (herramientas, Docker, móviles por USB), te
pregunta en qué plataformas estás y con qué puedes testear, y guarda un perfil con el que planifica
cada workspace nuevo. Al final te ofrece alertas en el móvil cuando salga un programa que encaje
contigo (`bountyproof radar init`).

Desde la terminal, la CLI no tiene dependencias:

```bash
uvx --from git+https://github.com/jorge-asenjo/bountyproof bountyproof new "Acme Corp" --platform ywh
```

Requisitos: Claude Code, Node.js 18+ (ejecuta el guard de scope), Python 3.10+ y git. Docker para los labs
white-box y el lab de demo. `bountyproof doctor` lo comprueba.

¿Sin cuenta de bug bounty? [`lab/`](lab/) ejecuta todo el pipeline contra OWASP Juice Shop en
`localhost`, con un scope que solo permite el lab.

## Cómo funciona

<p align="center">
  <img src="docs/assets/architecture.svg" alt="Orquestador, descubridores de solo lectura, case file, validador, juez de evidencias y envío humano" width="100%">
</p>

| Fase | Comando | Quién | Resultado |
|---|---|---|---|
| 0 Preparación | `/bountyproof:setup` | orquestador | reglas, modelo de amenazas, `scope.json` |
| 1 Reconocimiento | `/bountyproof:recon` | subagentes de solo lectura | mapa de superficie |
| 2 Descubrimiento | `/bountyproof:discover` | `discoverer` × shard | hipótesis con su dossier |
| 3 Validación | `/bountyproof:validate` | `validator` | confirmed / rejected / needs_validation |
| 3b Juez | `/bountyproof:judge` | `judge` | PASS / NEEDS_VALIDATION / DISCARD |
| 4a Borrador | `/bountyproof:draft` | orquestador | v1 solo con hechos verificados |
| 4b Claridad | `/bountyproof:clarity` | orquestador | v2 concisa en primera persona, mismos hechos |
| 4c Revisión | `/bountyproof:review` | `judge` nuevo | READY / NEEDS FIXES / DO NOT SUBMIT |
| 5 Calibración | `/bountyproof:calibrate` | orquestador | lecciones del triaje real |

## Uso responsable

Solo para pruebas autorizadas: programas en los que estás registrado, dentro de su scope y sus reglas.
Lee [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) antes de usarlo contra un objetivo real. Los workspaces de
programas privados se quedan en local.

Hecho por [Jorge Asenjo](https://github.com/jorge-asenjo). Licencia MIT.

[curl]: https://bleepingcomputer.com/news/security/curl-ending-bug-bounty-program-after-flood-of-ai-slop-reports/
