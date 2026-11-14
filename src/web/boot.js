// Primeiro módulo do app web: instala o Buffer antes de qualquer outro módulo do projeto rodar.
import { installBuffer } from './shims/buffer.js';
installBuffer();
