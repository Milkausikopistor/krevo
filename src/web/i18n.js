// Web wallet translations (zero dependencies).
//
// The English text is the key: t('Send') returns the translation for the current language, or the
// English text itself when there is none. Values may contain {placeholders} and simple HTML (<b>);
// callers pass already-escaped values for placeholders that end up in HTML.
//
// Adding a language: copy the `pt` block below, translate the values, add it to LANGUAGES and STRINGS.
// Messages that come from the wallet library itself (errors) stay in English for now.

export const LANGUAGES = { en: 'English', pt: 'Português' };
const LOCALES = { en: 'en-US', pt: 'pt-BR' };
const KEY = 'krevo-lang';

const pt = {
  // general
  'Copied': 'Copiado',
  'Could not copy automatically; please select the text.': 'Não foi possível copiar automaticamente; selecione o texto.',
  'Back': 'Voltar',
  'Continue': 'Continuar',
  'Cancel': 'Cancelar',
  'Close': 'Fechar',
  'Confirm': 'Confirmar',
  'Done': 'Pronto',
  'Copy': 'Copiar',
  'Share': 'Compartilhar',
  'Language': 'Idioma',
  'Password': 'Senha',
  'Checking…': 'Verificando…',
  'wrong password': 'senha incorreta',
  'private': 'privado',
  'transparent': 'transparente',
  'quantum-safe': 'quântico',
  // welcome and setup
  'Your wallet, on your device.': 'Sua carteira, no seu aparelho.',
  'Light and private: no node of your own, and the server you use <b>never gets your keys</b> — every payment you receive is checked against a proof before it counts in your balance.':
    'Leve e privada: sem nó próprio, e o servidor que você usa <b>nunca recebe suas chaves</b> — cada pagamento recebido é conferido contra uma prova antes de entrar no seu saldo.',
  'Light server': 'Servidor leve',
  'Any server works. It can neither spend your coins nor see your private balance.': 'Qualquer servidor serve. Ele não consegue gastar suas moedas nem ver seu saldo privado.',
  'Create a new wallet': 'Criar uma carteira nova',
  'Restore from recovery phrase': 'Restaurar pela frase de recuperação',
  'Back to saved wallets': 'Voltar às carteiras salvas',
  'Private by default': 'Privada por padrão',
  'Amounts and recipients stay hidden on the network.': 'Valores e destinatários ficam ocultos na rede.',
  'Your keys, your device': 'Suas chaves, seu aparelho',
  'Encrypted here; nothing goes to the server.': 'Cifradas aqui; nada vai para o servidor.',
  'Installable': 'Instalável',
  'Works as an app on phones and computers.': 'Funciona como app no celular e no computador.',
  'Checking the server…': 'Verificando o servidor…',
  'Recovery phrase': 'Frase de recuperação',
  'These 24 words <b>are</b> your wallet. Write them on paper, in order, and keep them somewhere safe. Whoever has the phrase controls the money — never take a photo, never type it into websites, never send it in a message.':
    'Estas 24 palavras <b>são</b> a sua carteira. Escreva-as no papel, em ordem, e guarde em lugar seguro. Quem tem a frase controla o dinheiro — nunca tire foto, nunca digite em sites, nunca envie por mensagem.',
  'Show the words': 'Mostrar as palavras',
  'I wrote them down': 'Já anotei',
  'Check the phrase': 'Confira a frase',
  'Type these words from your notes:': 'Digite estas palavras das suas anotações:',
  'Word #{n}': 'Palavra nº {n}',
  'A word does not match. Check your notes again.': 'Uma palavra não confere. Confira suas anotações.',
  'Restore': 'Restaurar',
  'Type your 12 or 24 word phrase, separated by spaces.': 'Digite sua frase de 12 ou 24 palavras, separadas por espaço.',
  'Password for this device': 'Senha deste aparelho',
  'It encrypts the wallet here in the browser. If you forget it, just restore from the phrase.': 'Ela cifra a carteira aqui no navegador. Se esquecer, é só restaurar pela frase.',
  'Password (at least 8 characters)': 'Senha (pelo menos 8 caracteres)',
  'Repeat the password': 'Repita a senha',
  'Network: <b>{network}</b> · server {server}': 'Rede: <b>{network}</b> · servidor {server}',
  'Create wallet': 'Criar carteira',
  'The password needs at least 8 characters.': 'A senha precisa de pelo menos 8 caracteres.',
  'The passwords do not match.': 'As senhas não conferem.',
  'Encrypting and creating…': 'Cifrando e criando…',
  'Wallet created': 'Carteira criada',
  'Welcome back': 'Olá de novo',
  'Wallet': 'Carteira',
  'Network <b>{network}</b> · {server}': 'Rede <b>{network}</b> · {server}',
  'Open': 'Abrir',
  'Create or restore another': 'Criar ou restaurar outra',
  'Opening…': 'Abrindo…',
  // top bar and navigation
  'syncing': 'sincronizando',
  'offline': 'sem conexão',
  'up to date': 'atualizado',
  'Refresh': 'Atualizar',
  'Lock': 'Bloquear',
  'Sections': 'Seções',
  'Home': 'Início',
  'Receive': 'Receber',
  'Send': 'Enviar',
  'Settings': 'Ajustes',
  // home
  'Change': 'Troco',
  'back from your payment': 'voltou do seu pagamento',
  ' · spent': ' · gasto',
  'Received': 'Recebido',
  'main address': 'endereço principal',
  ' (mining)': ' (mineração)',
  'Sent': 'Enviado',
  'Sent to @{name}': 'Enviado para @{name}',
  'Available balance': 'Saldo disponível',
  'Incoming: {amount} (waiting for confirmations)': 'Chegando: {amount} (aguardando confirmações)',
  'Waiting for proof: {amount}. The server reported it; the wallet only counts it after checking the proof (a few seconds).':
    'Aguardando prova: {amount}. O servidor informou; a carteira só conta depois de conferir a prova (alguns segundos).',
  'The server sent FALSE data about {tx}: {why}. That amount was ignored — consider switching servers.':
    'O servidor enviou dados FALSOS sobre {tx}: {why}. Esse valor foi ignorado — considere trocar de servidor.',
  'Servers disagree: {d}': 'Os servidores discordam: {d}',
  '2 servers compared: they agree.': '2 servidores comparados: eles concordam.',
  'Activity': 'Atividade',
  'Nothing here yet. Tap Receive to see your address.': 'Nada por aqui ainda. Toque em Receber para ver seu endereço.',
  // receive
  'Address type': 'Tipo de endereço',
  'Private': 'Privado',
  'Transparent': 'Transparente',
  'Quantum-safe': 'Quântico',
  'Request an amount (optional)': 'Pedir um valor (opcional)',
  'Private: the amount and the recipient stay hidden on the network. Each payment goes to a one-time address.':
    'Privado: o valor e o destinatário ficam ocultos na rede. Cada pagamento vai para um endereço de uso único.',
  'Transparent: amounts are visible on the network, as in Bitcoin. Prefer private.':
    'Transparente: os valores ficam visíveis na rede, como no Bitcoin. Prefira o privado.',
  'Quantum-safe (krq): every spend needs two signatures at once — Schnorr and ML-DSA (NIST FIPS 204) — so even a quantum computer cannot steal these coins. Amounts are visible, as in transparent.':
    'Quântico (krq): todo gasto precisa de duas assinaturas ao mesmo tempo — Schnorr e ML-DSA (NIST FIPS 204) —, então nem um computador quântico consegue roubar estas moedas. Os valores ficam visíveis, como no transparente.',
  'My Krevo address': 'Meu endereço Krevo',
  // send
  'To': 'Para',
  'krs1…, krv1… or @name': 'krs1…, krv1… ou @nome',
  'Scan QR code': 'Ler QR code',
  'Paste an address, a krevo: link or an @name.': 'Cole um endereço, um link krevo: ou um @nome.',
  'Amount (KRV)': 'Valor (KRV)',
  'Message (optional)': 'Mensagem (opcional)',
  'private addresses only — encrypted': 'só para endereços privados — cifrada',
  'Pay from': 'Pagar com',
  'Source': 'Origem',
  'Automatic': 'Automático',
  'Review': 'Revisar',
  'Looking up the name…': 'Procurando o nome…',
  'Name not registered.': 'Nome não registrado.',
  'Name expired (in grace period).': 'Nome vencido (em carência).',
  'Private address: amount and recipient hidden.': 'Endereço privado: valor e destinatário ocultos.',
  'Transparent address: amount visible.': 'Endereço transparente: valor visível.',
  'Quantum-safe address (transparent).': 'Endereço quântico (transparente).',
  'Multisig address (transparent).': 'Endereço multiassinatura (transparente).',
  'Valid address.': 'Endereço válido.',
  'Check the recipient.': 'Confira o destinatário.',
  'Invalid amount.': 'Valor inválido.',
  'Ambiguous amount: use a comma for decimals (e.g. 1000 or 2,5).': 'Valor ambíguo: use vírgula para os decimais (ex.: 1000 ou 2,5).',
  'Messages are only encrypted to private addresses (krs1…).': 'Mensagens só são cifradas para endereços privados (krs1…).',
  'automatic': 'automático',
  'private balance': 'saldo privado',
  'transparent balance': 'saldo transparente',
  'Confirm payment': 'Confirmar pagamento',
  'Address': 'Endereço',
  'Amount': 'Valor',
  'From': 'De',
  'Message': 'Mensagem',
  'The network fee is a fraction of a cent and is calculated when sending.': 'A taxa da rede é uma fração de centavo e é calculada no envio.',
  'Send now': 'Enviar agora',
  'Building and signing…': 'Montando e assinando…',
  'Proving and signing… (a private spend proves it belongs to ALL outputs of the network: it takes a few seconds)':
    'Provando e assinando… (um gasto privado prova que pertence a TODAS as saídas da rede: leva alguns segundos)',
  'Fee': 'Taxa',
  'Transaction': 'Transação',
  'waiting for the network…': 'aguardando a rede…',
  'Confirmed by the network in {s} s.': 'Confirmado pela rede em {s} s.',
  'Not confirmed yet; the wallet keeps watching.': 'Ainda não confirmado; a carteira continua acompanhando.',
  'Camera unavailable: {error}': 'Câmera indisponível: {error}',
  // settings
  'Server': 'Servidor',
  'Second server (optional)': 'Segundo servidor (opcional)',
  'run by another person or company': 'de outra pessoa ou empresa',
  'With two servers run by different owners, the wallet compares their answers: if one hides a payment or shows a coin that was already spent, the other exposes it.':
    'Com dois servidores de donos diferentes, a carteira compara as respostas: se um esconder um pagamento ou mostrar uma moeda já gasta, o outro denuncia.',
  'Save servers': 'Salvar servidores',
  'How to find your payments': 'Como encontrar seus pagamentos',
  'Scanning': 'Varredura',
  'On this device': 'Neste aparelho',
  'By the server': 'Pelo servidor',
  'By the server: saves battery, but the server receives your view key and sees what you receive (it still cannot spend).':
    'Pelo servidor: economiza bateria, mas o servidor recebe sua chave de visualização e vê o que você recebe (ainda assim não consegue gastar).',
  'On this device (recommended): the server receives no key and does not know which payments are yours.':
    'Neste aparelho (recomendado): o servidor não recebe nenhuma chave e não sabe quais pagamentos são seus.',
  'Security': 'Segurança',
  'Show recovery phrase': 'Mostrar a frase de recuperação',
  'Copy view key (read-only)': 'Copiar chave de visualização (só leitura)',
  'Remove the wallet from this device': 'Remover a carteira deste aparelho',
  'About': 'Sobre',
  'Network <b>{network}</b>. Light wallet: scanning happens here, and every amount received only counts after a proof (Merkle + {depth} blocks with proof of work on top).':
    'Rede <b>{network}</b>. Carteira leve: a varredura acontece aqui, e cada valor recebido só conta depois de uma prova (Merkle + {depth} blocos com prova de trabalho por cima).',
  'Multisig is available in the command-line wallet.': 'A multiassinatura está disponível na carteira de linha de comando.',
  'Quantum-safe addresses (krq) and multisig are available in the command-line wallet.': 'Endereços quânticos (krq) e multiassinatura estão disponíveis na carteira de linha de comando.',
  'enter the light server': 'informe o servidor leve',
  'the second server must be different from the first': 'o segundo servidor precisa ser diferente do primeiro',
  '{url} is on the {network} network': '{url} está na rede {network}',
  'Servers saved: the wallet will compare them': 'Servidores salvos: a carteira vai compará-los',
  'Server saved': 'Servidor salvo',
  'Show the phrase': 'Mostrar a frase',
  'Do not take a photo. Do not show it to anyone.': 'Não tire foto. Não mostre para ninguém.',
  'Remove from this device?': 'Remover deste aparelho?',
  'The money does not disappear — it is on the network. But without the recovery phrase you will <b>not</b> be able to open this wallet again.':
    'O dinheiro não some — ele está na rede. Mas sem a frase de recuperação você <b>não</b> vai conseguir abrir esta carteira de novo.',
  'Remove': 'Remover',
  'Wallet removed from this device': 'Carteira removida deste aparelho',
  // quantum protection
  'Quantum protection': 'Proteção quântica',
  'on': 'ligada',
  'off': 'desligada',
  'Classic transparent (krv)': 'Transparente clássico (krv)',
  'Quantum-safe (krq)': 'Quântico (krq)',
  'A large enough quantum computer could forge the classic signatures (Schnorr) of transparent coins. Coins on your krq address also need an ML-DSA signature, which it cannot forge. Private coins stay in the private pool.':
    'Um computador quântico grande o bastante poderia forjar as assinaturas clássicas (Schnorr) das moedas transparentes. As moedas no seu endereço krq também precisam de uma assinatura ML-DSA, que ele não consegue forjar. As moedas privadas continuam no pool privado.',
  'Move transparent coins to krq': 'Mover moedas transparentes para krq',
  'Move to the quantum-safe address?': 'Mover para o endereço quântico?',
  'Your mature classic transparent coins (krv) move to your krq address, and from now on the change of transparent payments goes there too. Private coins are not touched. The fee is a fraction of a cent.':
    'Suas moedas transparentes clássicas (krv) já maduras vão para o seu endereço krq, e daqui em diante o troco dos pagamentos transparentes também vai para lá. As moedas privadas não são mexidas. A taxa é uma fração de centavo.',
  'Move': 'Mover',
  'Moving…': 'Movendo…',
  'Moved {amount} to the quantum-safe address in {n} transaction(s).': '{amount} movidos para o endereço quântico em {n} transação(ões).',
  'Quantum mode is on. There were no mature classic coins to move yet.': 'O modo quântico está ligado. Ainda não havia moedas clássicas maduras para mover.',
  'Quantum-safe addresses need the WebAssembly core, which did not load in this browser.': 'Os endereços quânticos precisam do núcleo WebAssembly, que não carregou neste navegador.',
};

const STRINGS = { en: {}, pt };

function initial() {
  let saved = null;
  try { saved = localStorage.getItem(KEY); } catch { /* storage blocked */ }
  if (saved && STRINGS[saved]) return saved;
  const nav = (globalThis.navigator?.languages ?? [globalThis.navigator?.language ?? 'en']).map((l) => String(l).slice(0, 2).toLowerCase());
  return nav.find((l) => STRINGS[l]) ?? 'en';
}

let current = initial();

export const lang = () => current;
export const locale = () => LOCALES[current] ?? 'en-US';
export function setLang(l) {
  if (!STRINGS[l]) return;
  current = l;
  try { localStorage.setItem(KEY, l); } catch { /* storage blocked */ }
  if (globalThis.document) document.documentElement.lang = l;
}
if (globalThis.document) document.documentElement.lang = current;

/** Translates `text` (English) and fills {placeholders} from `vars`. */
export function t(text, vars) {
  let s = STRINGS[current]?.[text] ?? text;
  if (vars) s = s.replace(/\{(\w+)\}/g, (m, k) => (k in vars ? String(vars[k]) : m));
  return s;
}

/** "1,234.5" (English) → "1.234,5" (Portuguese): swaps the separators of an English-formatted number. */
export function localNumber(s) {
  if (current !== 'pt') return s;
  return s.replace(/[.,]/g, (c) => (c === '.' ? ',' : '.'));
}
