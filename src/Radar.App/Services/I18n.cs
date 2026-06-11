namespace Radar.App.Services;

/// <summary>
/// Idiomas PT-BR e EN. O texto-fonte (chave) é em PT-BR; o catálogo abaixo fornece a
/// tradução EN. Cobre todo o chrome da UI: menu, títulos, botões, headers, Settings, dossiê.
/// Strings GERADAS pelo collector/Core (explicações de score, origem, masquerading, timeline,
/// relatório) NÃO passam por aqui: são produzidas em inglês US e exibidas como dados.
/// Chave ausente cai no próprio PT-BR (degradação graciosa).
/// </summary>
public static class I18n
{
    public static string Language => AppServices.Settings?.Language ?? "pt-BR";

    public static bool IsEnglish => Language.StartsWith("en", StringComparison.OrdinalIgnoreCase);

    public static string T(string ptBr) => IsEnglish ? En.GetValueOrDefault(ptBr, ptBr) : ptBr;

    private static readonly Dictionary<string, string> En = new()
    {
        // Navegação / menu
        ["Painel"] = "Dashboard",
        ["Linha do tempo"] = "Timeline",
        ["Vida curta"] = "Short-lived",
        ["Assinaturas"] = "Signatures",
        ["Rede"] = "Network",
        ["Persistência"] = "Persistence",
        ["Árvore de processos"] = "Process tree",
        ["Busca"] = "Search",
        ["Configurações"] = "Settings",

        // Estado da coleta (rodapé / dashboard)
        ["Coleta ativa"] = "Collection active",
        ["Coleta parada"] = "Collection stopped",
        ["Coleta pausada"] = "Collection paused",
        ["Iniciar coleta"] = "Start collection",
        ["Pausar"] = "Pause",
        ["Retomar"] = "Resume",
        ["Encerrar"] = "Stop",

        // Dashboard
        ["Últimas 24 horas"] = "Last 24 hours",
        ["Últimos 7 dias"] = "Last 7 days",
        ["Processos novos"] = "New processes",
        ["Persistências adicionadas"] = "Persistence added",
        ["Top por score"] = "Top by score",
        ["Achados recentes"] = "Recent findings",
        ["Saúde da coleta"] = "Collection health",
        ["Atividade por dia (7d)"] = "Activity per day (7d)",
        ["dignos de nota (24h)"] = "noteworthy (24h)",
        ["Upload por processos não confiáveis (24h)"] = "Upload by untrusted processes (24h)",
        ["Nada digno de nota no período. É assim que uma máquina saudável deve aparecer."] =
            "Nothing noteworthy in this period. This is how a healthy machine should look.",
        ["Sem coletor, processos de vida curta que rodarem agora ficarão invisíveis para sempre."] =
            "Without the collector, short-lived processes that run now will be invisible forever.",
        ["{0:0} eventos/min · banco {1} · {2} execuções · RAM do coletor {3}"] =
            "{0:0} events/min · DB {1} · {2} executions · collector RAM {3}",
        ["⚠ SEM ELEVAÇÃO: coleta degradada (sem ETW de kernel)."] =
            "Warning: NO ELEVATION. Degraded collection (no kernel ETW).",

        // Filtros comuns
        ["Período"] = "Period",
        ["24 horas"] = "24 hours",
        ["7 dias"] = "7 days",
        ["30 dias"] = "30 days",
        ["Ordenar por"] = "Sort by",
        ["Recência"] = "Recency",
        ["Volume de rede"] = "Network volume",
        ["Repetições"] = "Repetitions",
        ["Mostrar suprimidos"] = "Show suppressed",
        ["Score mínimo"] = "Minimum score",
        ["Usuário/conta"] = "User/account",
        ["Só com rede"] = "Network only",

        // Short-lived
        ["execuções suprimidas"] = "suppressed executions",
        ["({0} binários efêmeros legítimos)"] = "({0} legitimate ephemeral binaries)",

        // Signatures
        ["Estado de assinatura"] = "Signature state",
        ["Todos os dignos de atenção"] = "All noteworthy",
        ["Assinatura inválida (alterado)"] = "Invalid signature (altered)",
        ["Certificado revogado"] = "Revoked certificate",
        ["Não assinado"] = "Unsigned",
        ["Auto-assinado"] = "Self-signed",
        ["Com ressalvas"] = "With caveats",
        ["Assinado e confiável"] = "Signed and trusted",
        ["Emissores raros nesta máquina"] = "Rare signers on this machine",
        ["Um certificado de empresa nunca vista assinando algo em %APPDATA% merece nota."] =
            "A certificate from a never-seen company signing something in %APPDATA% deserves attention.",

        // Network
        ["Só IP direto (sem DNS)"] = "Direct IP only (no DNS)",
        ["Upload > download"] = "Upload > download",
        ["Grafo de comunicação"] = "Communication graph",

        // Persistence
        ["Visão"] = "View",
        ["Diff temporal (o que mudou)"] = "Temporal diff (what changed)",
        ["Tudo que está ativo"] = "Everything active",
        ["Janela do diff"] = "Diff window",
        ["Abrir local"] = "Open location",

        // Process tree
        ["Linhagem navegável incluindo processos mortos. O Gerenciador de Tarefas só vê o presente."] =
            "Navigable lineage including dead processes. Task Manager only sees the present.",

        // Search
        ["nome, caminho, hash, domínio, IP, emissor de certificado, usuário…"] =
            "name, path, hash, domain, IP, certificate issuer, user...",

        // Faixas de score (UI)
        ["Informativo"] = "Informational",
        ["Atenção"] = "Attention",
        ["Suspeito"] = "Suspicious",
        ["Crítico"] = "Critical",

        // Estados de assinatura (UI). "Assinado e confiável" já definido no grupo Signatures
        ["Assinado com ressalvas"] = "Signed with caveats",
        ["Assinatura INVÁLIDA (alterado)"] = "INVALID signature (altered)",
        ["Certificado REVOGADO"] = "REVOKED certificate",
        ["Verificação pendente"] = "Verification pending",

        // Dossiê (ficha de processo): abas e ações
        ["Abrir dossiê"] = "Open dossier",
        ["Marcar confiável"] = "Mark trusted",
        ["Marcar suspeito"] = "Mark suspicious",
        ["Investigando"] = "Investigating",
        ["Copiar indicadores"] = "Copy indicators",
        ["Exportar relatório"] = "Export report",
        ["Plano de remoção"] = "Removal plan",
        ["Encerrar processo"] = "Kill process",
        ["Abrir local do arquivo"] = "Open file location",
        ["Pesquisar reputação"] = "Look up reputation",
        ["Mais ações"] = "More actions",
        ["Por que este score? (cada ponto é rastreável à evidência)"] =
            "Why this score? (every point is traceable to evidence)",
        ["Nenhum sinal de suspeição registrado para esta execução."] =
            "No suspicion signals recorded for this execution.",
        ["Origem e cadeia"] = "Origin and chain",
        ["Arquivos"] = "Files",
        ["Persistências"] = "Persistence",
        ["Execuções anteriores"] = "Previous executions",
        ["Anotações"] = "Notes",
        ["Cadeia de ancestralidade (snapshot na criação):"] = "Ancestry chain (snapshot at creation):",
        ["Suas anotações sobre esta investigação"] = "Your notes about this investigation",
        ["Salvar anotações"] = "Save notes",
        ["(abre no navegador, só o hash)"] = "(opens in the browser, hash only)",
        ["Evidência: "] = "Evidence: ",
        ["Plano de remoção assistida: {0}"] = "Assisted removal plan: {0}",
        ["marcado confiável"] = "marked trusted",
        ["marcado suspeito"] = "marked suspicious",
        ["investigando"] = "investigating",
        ["silenciado (marcado confiável)"] = "muted (marked trusted)",

        // Settings
        ["Coleta: o que o Radar observa"] = "Collection: what Radar observes",
        ["Perfil de coleta"] = "Collection profile",
        ["Completo"] = "Complete",
        ["Equilibrado"] = "Balanced",
        ["Mínimo"] = "Minimal",
        ["Personalizado"] = "Custom",
        ["Mudanças aplicam sem reiniciar o coletor e ficam registradas no log operacional."] =
            "Changes apply without restarting the collector and are recorded in the operational log.",
        ["Exclusões de coleta (privacidade ativa)"] = "Collection exclusions (active privacy)",
        ["O que for excluído aqui NÃO é sequer gravado em disco. Diferente da lista de confiança, que apenas filtra a exibição."] =
            "Whatever is excluded here is NOT even written to disk. Unlike the trust list, which only filters the display.",
        ["prefixo de caminho (ex.: D:\\Trabalho\\Sigiloso)"] = "path prefix (e.g.: D:\\Work\\Confidential)",
        ["Adicionar"] = "Add",
        ["Remover selecionada"] = "Remove selected",
        ["Armazenamento dos dados"] = "Data storage",
        ["nova raiz de dados…"] = "new data root...",
        ["Validar e migrar"] = "Validate and migrate",
        ["Retenção de eventos brutos (dias)"] = "Raw event retention (days)",
        ["Teto do banco (MB)"] = "Database cap (MB)",
        ["Frequência das ações periódicas"] = "Periodic action frequency",
        ["Varredura de persistência (min)"] = "Persistence scan (min)",
        ["Lote de assinaturas (s)"] = "Signature batch (s)",
        ["Checkpoint do banco (s)"] = "Database checkpoint (s)",
        ["Máximo de notificações por hora (antifadiga)"] = "Max notifications per hour (anti-fatigue)",
        ["Ciclo de vida e notificações"] = "Lifecycle and notifications",
        ["Encerrar a coleta ao fechar a interface"] = "Stop collection when the interface closes",
        ["⚠ Com isso ligado, processos de vida curta que rodarem com o app fechado ficarão para sempre invisíveis. O produto depende de coleta contínua."] =
            "Warning: with this on, short-lived processes that run while the app is closed will be invisible forever. The product depends on continuous collection.",
        ["Iniciar a coleta junto com o Windows"] = "Start collection with Windows",
        ["Toast para achados em tempo real"] = "Toast for real-time findings",
        ["Limiar de notificação"] = "Notification threshold",
        ["Apenas Crítico (padrão antifadiga)"] = "Critical only (anti-fatigue default)",
        ["Suspeito ou acima"] = "Suspicious or above",
        ["Atenção ou acima"] = "Attention or above",
        ["Privacidade e idioma"] = "Privacy and language",
        ["Zero telemetria por padrão. Nenhuma consulta externa sem opt-in explícito e granular."] =
            "Zero telemetry by default. No external query without explicit, granular opt-in.",
        ["Atualizar listas curadas online (semanal)"] = "Update curated lists online (weekly)",
        ["Consulta de reputação de hash por API (requer chave própria)"] =
            "Hash reputation lookup via API (requires your own key)",
        ["Idioma / Language"] = "Language / Idioma",
        ["Limiar de vida curta (segundos)"] = "Short-lived threshold (seconds)",
        ["Raiz atual:"] = "Current root:",
        ["Banco: {0} · {1} execuções · eventos de {2} até {3}"] =
            "Database: {0} · {1} executions · events from {2} to {3}",
        ["Custo estimado: varredura de persistência ≈{0:0} execuções/dia (CPU ~1s cada); checkpoint ≈{1:0}/hora (I/O leve). Intervalos menores = detecção mais rápida, mais CPU/I-O."] =
            "Estimated cost: persistence scan ≈{0:0} runs/day (CPU ~1s each); checkpoint ≈{1:0}/hour (light I/O). Smaller intervals = faster detection, more CPU/I-O.",
        ["✓ Migração concluída ({0} arquivos). Reabra o Radar e inicie a coleta para usar a nova raiz."] =
            "✓ Migration complete ({0} files). Reopen Radar and start collection to use the new root.",
        ["✗ Falha na migração:"] = "✗ Migration failed:",
        ["Operação e suporte"] = "Operation and support",
        ["Abrir pasta de logs"] = "Open logs folder",
        ["Abrir settings.json (pesos do score etc.)"] = "Open settings.json (score weights, etc.)",
        ["Habilitar auditoria 4688 do Windows"] = "Enable Windows 4688 auditing",
        ["Limitações declaradas: rootkits em kernel podem cegar qualquer monitor user-mode, inclusive este; o Radar não inspeciona conteúdo de tráfego (vê com quem e quanto, não o quê); score alto não é veredito; a coleta só enxerga a partir da instalação; não substitui antivírus."] =
            "Declared limitations: kernel rootkits can blind any user-mode monitor, including this one; Radar does not inspect traffic content (it sees who and how much, not what); a high score is not a verdict; collection only sees from installation onward; it does not replace antivirus.",
        ["Módulos: "] = "Modules: ",

        // Módulos de coleta (nomes)
        ["Processos (núcleo)"] = "Processes (core)",
        ["Rede (TCP/UDP por processo)"] = "Network (TCP/UDP per process)",
        ["DNS (consultas por processo)"] = "DNS (queries per process)",
        ["Arquivos: leituras sensíveis"] = "Files: sensitive reads",
        ["Arquivos: drops de executáveis/scripts"] = "Files: executable/script drops",
        ["Arquivos: detecção de auto-deleção"] = "Files: self-deletion detection",
        ["Módulos / Image Load"] = "Modules / Image Load",
        ["Varredura de persistência"] = "Persistence scan",
        ["Baseline e prevalência"] = "Baseline and prevalence",
        ["Se desligado: "] = "If turned off: ",

        // Módulos: o que se perde
        ["É a fundação do produto: sem criação/término de processos, praticamente todas as features ficam suspensas."] =
            "It is the foundation of the product: without process start/stop, practically all features are suspended.",
        ["Desativa o replay de comunicação, os sinais de exfiltração e o grafo de rede."] =
            "Disables communication replay, exfiltration signals and the network graph.",
        ["Sem consultas DNS, conexões não são ligadas a domínios e a marcação de \"IP direto\" perde sentido."] =
            "Without DNS queries, connections are not linked to domains and the \"direct IP\" flag loses meaning.",
        ["Perde o sinal mais forte de info-stealer: leitura de cofres de credenciais, carteiras e tokens."] =
            "Loses the strongest info-stealer signal: reads of credential vaults, wallets and tokens.",
        ["Perde a linhagem de arquivos: quem criou qual executável e o que ele virou quando rodou."] =
            "Loses file lineage: who created which executable and what it became when it ran.",
        ["Perde a detecção de anti-forense (binários que se apagam após executar)."] =
            "Loses anti-forensic detection (binaries that delete themselves after running).",
        ["Perde a detecção de DLL não assinada carregada em processo confiável (sideloading)."] =
            "Loses detection of an unsigned DLL loaded into a trusted process (sideloading).",
        ["Sem varredura de autoruns, novas persistências não são detectadas nem correlacionadas."] =
            "Without autoruns scanning, new persistence is neither detected nor correlated.",
        ["Sem baseline, os atributos de novidade (\"nunca visto antes\") e prevalência param de funcionar."] =
            "Without baseline, the novelty (\"never seen before\") and prevalence attributes stop working.",

        // Primeiro uso (assistente)
        ["Bem-vindo ao Radar"] = "Welcome to Radar",
        ["Começar"] = "Start",
        ["Agora não"] = "Not now",
        ["Perfil de coleta inicial"] = "Initial collection profile",
        ["Equilibrado (recomendado)"] = "Balanced (recommended)",
        ["O Radar registra continuamente o ciclo de vida de processos (criação, atividade, término) para dar visibilidade a programas de vida curta que passam despercebidos. Toda coleta e análise acontece NESTA máquina; nada é enviado para fora sem seu opt-in explícito."] =
            "Radar continuously records the lifecycle of processes (creation, activity, termination) to give visibility to short-lived programs that go unnoticed. All collection and analysis happens ON THIS machine; nothing is sent out without your explicit opt-in.",
        ["Habilitar a auditoria de criação de processos do Windows (evento 4688) como fonte complementar. Requer elevação."] =
            "Enable Windows process-creation auditing (event 4688) as a complementary source. Requires elevation.",
        ["Os dados (banco de eventos, configurações e logs) ficam em:\n{0}\nVocê pode mudar o local e desligar qualquer módulo de coleta nas Configurações."] =
            "Your data (event database, settings and logs) lives at:\n{0}\nYou can change the location and turn off any collection module in Settings.",
        ["Limitações que o Radar declara abertamente: não é antivírus, não bloqueia nem remove; score alto não é veredito de malware; malware com privilégio de kernel pode cegar qualquer monitor em user-mode, inclusive este."] =
            "Limitations Radar states openly: it is not an antivirus, it does not block or remove; a high score is not a malware verdict; malware with kernel privilege can blind any user-mode monitor, including this one.",

        // Diálogos / ações
        ["Fechar"] = "Close",
        ["Checklist com tudo que o Radar sabe. A execução das remoções fica com você (ou com seu antivírus, após denúncia)."] =
            "Checklist with everything Radar knows. Carrying out the removals is up to you (or your antivirus, after reporting).",
    };
}
