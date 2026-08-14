// i18n.js — internationalization for MasPassword (vanilla ES module, no build step).
//
// Locales: es (default), en, fr. Flat string catalogs with dot.notation keys.
// All three catalogs MUST keep identical key sets (enforced by tests/i18n.test.js).
//
// Usage:
//   import { initI18n, t, applyI18n, setLocale } from '/i18n.js';
//   initI18n();
//   t('toast.copied');                          // -> 'Copiado'
//   t('items.lastEdited', { name: 'Ana', when: 'ayer' });
//   applyI18n();                                 // translate [data-i18n*] nodes
//
// Markup contract:
//   <span data-i18n="sidebar.vaults"></span>              -> textContent
//   <input data-i18n-placeholder="items.search.placeholder"> -> placeholder attr
//   <button data-i18n-title="actions.copy">...</button>       -> title attr

export const LOCALES = ['es', 'en', 'fr'];

const STORAGE_KEY = 'mp-locale';
const DEFAULT_LOCALE = 'es';

// ---------------------------------------------------------------------------
// Catalogs (flat, dot.notation keys — key order kept identical across locales)
// ---------------------------------------------------------------------------

const es = {
  // App / global
  'app.name': 'Vault Internal',
  'app.tagline': 'Gestor de contraseñas de conocimiento cero.',
  'app.zeroKnowledge': 'Tus contraseñas nunca salen de tu dispositivo sin cifrar.',
  'version.running': 'Version {v}',
  'settings.title': 'Ajustes',
  'settings.language': 'Idioma',
  'settings.theme': 'Tema',
  'settings.global': 'Ajustes globales',
  'settings.defaultTheme': 'Tema por defecto',
  'locale.es': 'Español',
  'locale.en': 'English',
  'locale.fr': 'Français',

  // Auth — login / signup
  'auth.email': 'Email',
  'auth.email.placeholder': 'tu@ejemplo.com',
  'auth.masterPassword': 'Contraseña maestra',
  'auth.masterPassword.placeholder': 'Tu contraseña maestra',
  'auth.login': 'Iniciar sesión',
  'auth.noAccount': '¿No tienes cuenta?',
  'auth.signup': 'Regístrate',
  'auth.forgotPassword': '¿Has olvidado tu contraseña?',
  'auth.signup.title': 'Crear cuenta',
  'auth.signup.hint': 'Tu contraseña maestra se usa para derivar las claves de cifrado localmente. Nunca la vemos.',
  'auth.signup.passwordPlaceholder': 'Elige una contraseña fuerte',
  'auth.confirmPassword': 'Confirmar contraseña',
  'auth.confirmPassword.placeholder': 'Confirma la contraseña',
  'auth.haveAccount': '¿Ya tienes cuenta?',
  'auth.unlock': 'Desbloquear',
  'auth.iap.unlockHint': 'Autenticado con Google IAP. Introduce tu contraseña maestra para desbloquear tu caja fuerte.',
  'auth.iap.setupTitle': 'Configurar cifrado',
  'auth.iap.setupHint': 'Autenticado con Google IAP. Crea una contraseña maestra para cifrar tus datos. Nunca la vemos.',

  // Recovery key screen (after signup / recovery)
  'recovery.title': 'Guarda tu clave de recuperación',
  'recovery.hint': 'Esta clave te permite recuperar tu cuenta si olvidas tu contraseña maestra. Guárdala en un lugar seguro: solo se mostrará una vez.',
  'recovery.copy': 'Copiar al portapapeles',
  'recovery.saved': 'He guardado esta clave de recuperación',
  'recovery.continue': 'Continuar',

  // Account recovery (forgot password)
  'recover.title': 'Recuperación de cuenta',
  'recover.hint': 'Introduce tu email, tu clave de recuperación y una nueva contraseña maestra para recuperar el acceso.',
  'recover.key': 'Clave de recuperación',
  'recover.key.placeholder': 'Pega tu clave de recuperación',
  'recover.newPassword': 'Nueva contraseña maestra',
  'recover.newPassword.placeholder': 'Elige una nueva contraseña',
  'recover.confirm': 'Confirmar nueva contraseña',
  'recover.confirm.placeholder': 'Confirma la nueva contraseña',
  'recover.submit': 'Restablecer contraseña',
  'recover.backToLogin': 'Volver a iniciar sesión',

  // Lock screen
  'lock.title': 'Caja fuerte bloqueada',
  'lock.hint': 'Bloqueada por tu seguridad. Introduce tu contraseña maestra para desbloquear.',
  'lock.logoutInstead': 'Prefiero cerrar sesión',

  // Sidebar
  'sidebar.vaults': 'Cajas fuertes',
  'sidebar.newVault': '+ Nueva caja fuerte',
  'sidebar.teams': 'Equipos',
  'sidebar.newTeam': '+ Nuevo equipo',
  'sidebar.tools': 'Herramientas',
  'sidebar.watchtower': 'Panel de seguridad',
  'sidebar.generator': 'Generador de contraseñas',
  'sidebar.quickSearch': 'Búsqueda rápida',
  'sidebar.darkMode': 'Modo oscuro',
  'sidebar.lightMode': 'Modo claro',
  'sidebar.lockVault': 'Bloquear caja fuerte',
  'sidebar.logout': 'Cerrar sesión',

  // Item list
  'items.search.placeholder': 'Buscar elementos...',
  'items.empty': 'Aún no hay elementos',
  'items.new': '+ Nuevo elemento',
  'items.import': 'Importar',
  'items.selectPrompt': 'Selecciona un elemento para ver los detalles',
  'items.untitled': 'Sin título',
  'items.favorites': 'Favoritos',
  'items.favorite': 'Favorito',
  'items.hasTotp': 'Tiene TOTP',
  'items.lastEdited': 'Editado por {name} {when}',
  'items.attachments': 'Adjuntos',
  'items.attachments.add': 'Añadir adjunto',
  'items.attachments.tooBig': 'El archivo es demasiado grande (máx. 2 MB)',
  'items.customFields': 'Campos personalizados',
  'items.customFields.add': 'Añadir campo',
  'items.customFields.label': 'Etiqueta',
  'items.customFields.value': 'Valor',
  'items.icon.change': 'Cambiar icono',

  // Item types
  'type.login': 'Inicio de sesión',
  'type.card': 'Tarjeta de crédito',
  'type.note': 'Nota segura',
  'type.identity': 'Identidad',

  // Common actions
  'actions.copy': 'Copiar',
  'actions.show': 'Mostrar',
  'actions.hide': 'Ocultar',
  'actions.edit': 'Editar',
  'actions.delete': 'Eliminar',
  'actions.close': 'Cerrar',
  'actions.cancel': 'Cancelar',
  'actions.save': 'Guardar',
  'actions.create': 'Crear',
  'actions.add': 'Añadir',
  'actions.done': 'Hecho',
  'detail.title': 'Detalles',

  // Fields (form labels + detail rows)
  'fields.title': 'Título',
  'fields.title.placeholder': 'p. ej. GitHub, Gmail',
  'fields.username': 'Usuario',
  'fields.usernameOrEmail': 'Usuario / Email',
  'fields.password': 'Contraseña',
  'fields.website': 'Sitio web',
  'fields.url': 'URL',
  'fields.totp': 'Contraseña de un solo uso',
  'fields.totpSecret': 'Secreto TOTP (contraseña de un solo uso)',
  'fields.totpSecret.placeholder': 'Secreto Base32, p. ej. JBSWY3DPEHPK3PXP',
  'fields.notes': 'Notas',
  'fields.notes.placeholder': 'Notas opcionales',
  'fields.tags': 'Etiquetas',
  'fields.tags.hint': '(separadas por comas)',
  'fields.tags.placeholder': 'trabajo, social, finanzas',
  'fields.email': 'Email',
  'fields.cardholder': 'Titular de la tarjeta',
  'fields.cardNumber': 'Número de tarjeta',
  'fields.cardBrand': 'Marca',
  'fields.cardExpiry': 'Caducidad',
  'fields.cvv': 'CVV',
  'fields.pin': 'PIN',
  'fields.fullName': 'Nombre completo',
  'fields.phone': 'Teléfono',
  'fields.address': 'Dirección',
  'fields.company': 'Empresa',

  // Item form
  'form.newItem': 'Nuevo elemento',
  'form.editItem': 'Editar elemento',
  'form.markFavorite': 'Marcar como favorito',
  'form.generate': 'Generar',

  // TOTP
  'totp.copyCode': 'Copiar código',
  'totp.invalid': 'No válido',

  // Password health / breach check
  'health.title': 'Salud de la contraseña',
  'breach.check': 'Comprobar filtraciones',
  'breach.checking': 'Comprobando…',
  'breach.found': 'Encontrada en {count} filtraciones conocidas: cámbiala.',
  'breach.notFound': 'No aparece en filtraciones conocidas.',
  'breach.unavailable': 'Comprobación de filtraciones no disponible (¿sin conexión?)',

  // Strength labels
  'strength.veryWeak': 'muy débil',
  'strength.weak': 'débil',
  'strength.fair': 'aceptable',
  'strength.strong': 'fuerte',
  'strength.veryStrong': 'muy fuerte',
  'strength.bits': '{bits} bits',
  'strength.cracksIn': 'se descifra en ~{time}',

  // Password history
  'history.title': 'Historial de contraseñas',
  'history.empty': 'No hay versiones anteriores.',
  'history.noPassword': '(sin contraseña)',

  // Vaults
  'vault.new': 'Nueva caja fuerte',
  'vault.name': 'Nombre de la caja fuerte',
  'vault.name.placeholder': 'p. ej. Personal, Trabajo',
  'vault.created': 'Caja fuerte creada',
  'vault.notFound': 'Caja fuerte no encontrada',
  'vault.shared': 'Compartida',
  'vault.sharedWith': 'Compartida con',

  // Teams
  'teams.new': 'Nuevo equipo',
  'teams.name': 'Nombre del equipo',
  'teams.name.placeholder': 'p. ej. Ingeniería, Diseño',
  'teams.members': 'Miembros',
  'teams.addMember': 'Añadir miembro',
  'teams.memberEmail.placeholder': 'miembro@ejemplo.com',
  'teams.vaults': 'Cajas fuertes del equipo',
  'teams.createVault': 'Crear caja fuerte',
  'teams.vault.new': 'Nueva caja fuerte de equipo',
  'teams.vault.name.placeholder': 'p. ej. Contraseñas compartidas',
  'teams.noMembers': 'No hay miembros',
  'teams.noVaults': 'No hay cajas fuertes',
  'teams.promote': 'Ascender a administrador',
  'teams.demote': 'Degradar a miembro',
  'teams.role.admin': 'Administrador',
  'teams.role.member': 'Miembro',
  'teams.role.owner': 'Propietario',
  'teams.role.pending': 'Pendiente',
  'teams.removeMember': 'Quitar miembro',
  'teams.removeConfirm': '¿Quitar a este miembro?',
  'teams.notFound': 'Equipo no encontrado',

  // Import / export
  'import.title': 'Importar desde 1Password',
  'import.description': 'Selecciona un archivo .csv o .1pif exportado desde 1Password.',
  'import.chooseFile': 'Elegir archivo...',
  'import.noItems': 'No se han encontrado elementos en el archivo.',
  'import.found': 'Se han encontrado {count} elementos — Formato: {format}',
  'import.start': 'Importar',
  'import.importing': 'Importando...',
  'import.progress': '{done} de {total} elementos procesados...',
  'import.complete': 'Importación completada',
  'import.summary': '{imported} de {total} elementos importados correctamente.',
  'import.errors': '{count} errores.',
  'import.failed': 'La importación ha fallado: {error}',
  'export.title': 'Exportar',

  // Command palette
  'cmd.placeholder': 'Busca elementos o escribe un comando…',
  'cmd.indexing': 'Indexando tus cajas fuertes…',
  'cmd.noMatches': 'Sin coincidencias',
  'cmd.navigate': 'navegar',
  'cmd.open': 'abrir',
  'cmd.close': 'cerrar',
  'cmd.action': 'acción',
  'cmd.toggleTheme': 'Alternar modo oscuro',
  'search.global.placeholder': 'Buscar en todas las cajas fuertes…',

  // Watchtower (security dashboard)
  'watchtower.title': 'Panel de seguridad',
  'watchtower.scanning': 'Analizando tus cajas fuertes…',
  'watchtower.summary': 'Analizados {logins} inicios de sesión en {vaults} cajas fuertes.',
  'watchtower.allClear': 'No se han encontrado contraseñas débiles, reutilizadas ni antiguas.',
  'watchtower.weak': 'Contraseñas débiles',
  'watchtower.weak.note': 'Fáciles de adivinar: refuérzalas.',
  'watchtower.reused': 'Contraseñas reutilizadas',
  'watchtower.reused.note': 'La misma contraseña protege varios elementos.',
  'watchtower.aging': 'Contraseñas antiguas',
  'watchtower.aging.note': 'Sin cambios desde hace más de un año.',
  'watchtower.breaches': 'Contraseñas filtradas',
  'watchtower.breaches.note': 'Aparecen en filtraciones de datos conocidas: cámbialas ya.',
  'watchtower.breaches.checking': 'Consultando Have I Been Pwned…',
  'watchtower.breaches.none': 'Ninguna contraseña aparece en filtraciones conocidas.',
  'watchtower.breaches.unavailable': 'Comprobación de filtraciones no disponible (sin conexión).',
  'watchtower.breaches.count': 'en {count} filtraciones',
  'watchtower.duplicates': 'Elementos duplicados',
  'watchtower.duplicates.note': 'Varios elementos con el mismo título, usuario y sitio.',

  // Password generator
  'generator.title': 'Generador de contraseñas',
  'generator.regenerate': 'Regenerar',
  'generator.mode.password': 'Contraseña',
  'generator.mode.passphrase': 'Frase de contraseña',
  'generator.length': 'Longitud',
  'generator.words': 'Palabras',
  'generator.noAmbiguous': 'Sin caracteres ambiguos',
  'generator.capitalize': 'Mayúscula inicial',
  'generator.addNumber': 'Añadir número',
  'generator.use': 'Usar contraseña',

  // One-time share links
  'share.title': 'Compartir elemento',
  'share.create': 'Crear enlace',
  'share.expires': 'Caduca',
  'share.copy': 'Copiar enlace',
  'share.oneUse': 'Un solo uso',
  'share.revoked': 'Enlace revocado',
  'share.open.title': 'Elemento compartido',
  'share.open.gone': 'Este enlace ha caducado o ya se ha usado.',

  // Toasts
  'toast.copied': 'Copiado',
  'toast.saved': 'Guardado',
  'toast.copyFailed': 'Error al copiar',
  'toast.loggedIn': 'Sesión iniciada',
  'toast.loginFailed': 'Error al iniciar sesión: {error}',
  'toast.accountCreated': '¡Cuenta creada!',
  'toast.unlocked': 'Desbloqueado',
  'toast.wrongMasterPassword': 'Contraseña maestra incorrecta',
  'toast.fillAllFields': 'Rellena todos los campos',
  'toast.passwordsMismatch': 'Las contraseñas no coinciden',
  'toast.passwordTooShort': 'La contraseña debe tener al menos 8 caracteres',
  'toast.enterMasterPassword': 'Introduce tu contraseña maestra',
  'toast.enterName': 'Introduce un nombre',
  'toast.enterTitle': 'Introduce un título',
  'toast.enterTeamName': 'Introduce un nombre de equipo',
  'toast.enterEmail': 'Introduce un email',
  'toast.selectVaultFirst': 'Selecciona primero una caja fuerte',
  'toast.itemSaved': 'Elemento guardado',
  'toast.itemUpdated': 'Elemento actualizado',
  'toast.itemDeleted': 'Elemento eliminado',
  'toast.itemNotFound': 'Elemento no encontrado',
  'toast.deleteConfirm': '¿Eliminar este elemento? Esta acción no se puede deshacer.',
  'toast.favoriteAdded': 'Añadido a favoritos',
  'toast.favoriteRemoved': 'Quitado de favoritos',
  'toast.teamCreated': 'Equipo creado',
  'toast.teamVaultCreated': 'Caja fuerte de equipo creada',
  'toast.memberAdded': 'Miembro añadido',
  'toast.memberInvited': 'Miembro invitado (pendiente de configurar el cifrado)',
  'toast.memberRemoved': 'Miembro eliminado',
  'toast.promoted': 'Ascendido a administrador',
  'toast.demoted': 'Degradado a miembro',
  'toast.passwordResetSuccess': '¡Contraseña restablecida correctamente!',
  'toast.recoveryFailed': 'La recuperación ha fallado: {error}',
  'toast.invalidRecoveryKey': 'Clave de recuperación no válida',
  'toast.encryptionSetup': 'Cifrado configurado correctamente',
  'toast.setupFailed': 'La configuración ha fallado: {error}',

  // Onboarding — welcome + first-steps checklist
  'onboarding.title': 'Primeros pasos',
  'onboarding.progress': '{done} de {total}',
  'onboarding.dismiss': 'Ocultar la guía',
  'onboarding.complete': 'Todo listo. Ya tienes lo básico.',
  'onboarding.step.vault': 'Crea tu primera caja fuerte',
  'onboarding.step.item': 'Guarda tu primera contraseña',
  'onboarding.step.generator': 'Prueba el generador',
  'onboarding.step.extension': 'Instala la extensión del navegador',
  'onboarding.step.team': 'Crea un equipo y comparte',
  'onboarding.welcome.title': 'Te damos la bienvenida',
  'onboarding.welcome.intro': 'Tres cosas antes de empezar:',
  'onboarding.welcome.zk': 'Todo se cifra en tu dispositivo. Ni el servidor ni los administradores ven tus datos en claro.',
  'onboarding.welcome.vaults': 'Tus contraseñas viven en cajas fuertes. Puedes compartirlas con equipos sin romper el cifrado.',
  'onboarding.welcome.guide': 'La guía de primeros pasos del menú lateral te acompaña hasta que domines lo básico.',
  'onboarding.welcome.start': 'Crear mi primera caja fuerte',
  'onboarding.welcome.skip': 'Explorar por mi cuenta',
};

const en = {
  // App / global
  'app.name': 'Vault Internal',
  'app.tagline': 'Zero-Knowledge Password Manager.',
  'app.zeroKnowledge': 'Your passwords never leave your device unencrypted.',
  'version.running': 'Version {v}',
  'settings.title': 'Settings',
  'settings.language': 'Language',
  'settings.theme': 'Theme',
  'settings.global': 'Global Settings',
  'settings.defaultTheme': 'Default theme',
  'locale.es': 'Español',
  'locale.en': 'English',
  'locale.fr': 'Français',

  // Auth — login / signup
  'auth.email': 'Email',
  'auth.email.placeholder': 'you@example.com',
  'auth.masterPassword': 'Master Password',
  'auth.masterPassword.placeholder': 'Your master password',
  'auth.login': 'Log in',
  'auth.noAccount': "Don't have an account?",
  'auth.signup': 'Sign up',
  'auth.forgotPassword': 'Forgot password?',
  'auth.signup.title': 'Create Account',
  'auth.signup.hint': 'Your master password is used to derive encryption keys locally. We never see it.',
  'auth.signup.passwordPlaceholder': 'Choose a strong password',
  'auth.confirmPassword': 'Confirm Password',
  'auth.confirmPassword.placeholder': 'Confirm password',
  'auth.haveAccount': 'Already have an account?',
  'auth.unlock': 'Unlock',
  'auth.iap.unlockHint': 'Authenticated via Google IAP. Enter your master password to unlock your vault.',
  'auth.iap.setupTitle': 'Set Up Encryption',
  'auth.iap.setupHint': 'Authenticated via Google IAP. Create a master password to encrypt your data. We never see it.',

  // Recovery key screen (after signup / recovery)
  'recovery.title': 'Save Your Recovery Key',
  'recovery.hint': 'This key allows you to recover your account if you forget your master password. Save it somewhere safe — it will only be shown once.',
  'recovery.copy': 'Copy to clipboard',
  'recovery.saved': 'I have saved this recovery key',
  'recovery.continue': 'Continue',

  // Account recovery (forgot password)
  'recover.title': 'Account Recovery',
  'recover.hint': 'Enter your email, recovery key, and a new master password to regain access.',
  'recover.key': 'Recovery Key',
  'recover.key.placeholder': 'Paste your recovery key',
  'recover.newPassword': 'New Master Password',
  'recover.newPassword.placeholder': 'Choose a new password',
  'recover.confirm': 'Confirm New Password',
  'recover.confirm.placeholder': 'Confirm new password',
  'recover.submit': 'Reset Password',
  'recover.backToLogin': 'Back to login',

  // Lock screen
  'lock.title': 'Vault Locked',
  'lock.hint': 'Locked for your security. Enter your master password to unlock.',
  'lock.logoutInstead': 'Log out instead',

  // Sidebar
  'sidebar.vaults': 'Vaults',
  'sidebar.newVault': '+ New Vault',
  'sidebar.teams': 'Teams',
  'sidebar.newTeam': '+ New Team',
  'sidebar.tools': 'Tools',
  'sidebar.watchtower': 'Security dashboard',
  'sidebar.generator': 'Password generator',
  'sidebar.quickSearch': 'Quick search',
  'sidebar.darkMode': 'Dark mode',
  'sidebar.lightMode': 'Light mode',
  'sidebar.lockVault': 'Lock vault',
  'sidebar.logout': 'Log out',

  // Item list
  'items.search.placeholder': 'Search items...',
  'items.empty': 'No items yet',
  'items.new': '+ New Item',
  'items.import': 'Import',
  'items.selectPrompt': 'Select an item to view details',
  'items.untitled': 'Untitled',
  'items.favorites': 'Favorites',
  'items.favorite': 'Favorite',
  'items.hasTotp': 'Has TOTP',
  'items.lastEdited': 'Edited by {name} {when}',
  'items.attachments': 'Attachments',
  'items.attachments.add': 'Add attachment',
  'items.attachments.tooBig': 'File is too big (max 2 MB)',
  'items.customFields': 'Custom fields',
  'items.customFields.add': 'Add field',
  'items.customFields.label': 'Label',
  'items.customFields.value': 'Value',
  'items.icon.change': 'Change icon',

  // Item types
  'type.login': 'Login',
  'type.card': 'Credit Card',
  'type.note': 'Secure Note',
  'type.identity': 'Identity',

  // Common actions
  'actions.copy': 'Copy',
  'actions.show': 'Show',
  'actions.hide': 'Hide',
  'actions.edit': 'Edit',
  'actions.delete': 'Delete',
  'actions.close': 'Close',
  'actions.cancel': 'Cancel',
  'actions.save': 'Save',
  'actions.create': 'Create',
  'actions.add': 'Add',
  'actions.done': 'Done',
  'detail.title': 'Details',

  // Fields (form labels + detail rows)
  'fields.title': 'Title',
  'fields.title.placeholder': 'e.g. GitHub, Gmail',
  'fields.username': 'Username',
  'fields.usernameOrEmail': 'Username / Email',
  'fields.password': 'Password',
  'fields.website': 'Website',
  'fields.url': 'URL',
  'fields.totp': 'One-Time Password',
  'fields.totpSecret': 'One-Time Password Secret (TOTP)',
  'fields.totpSecret.placeholder': 'Base32 secret, e.g. JBSWY3DPEHPK3PXP',
  'fields.notes': 'Notes',
  'fields.notes.placeholder': 'Optional notes',
  'fields.tags': 'Tags',
  'fields.tags.hint': '(comma-separated)',
  'fields.tags.placeholder': 'work, social, finance',
  'fields.email': 'Email',
  'fields.cardholder': 'Cardholder',
  'fields.cardNumber': 'Card Number',
  'fields.cardBrand': 'Brand',
  'fields.cardExpiry': 'Expires',
  'fields.cvv': 'CVV',
  'fields.pin': 'PIN',
  'fields.fullName': 'Full Name',
  'fields.phone': 'Phone',
  'fields.address': 'Address',
  'fields.company': 'Company',

  // Item form
  'form.newItem': 'New Item',
  'form.editItem': 'Edit Item',
  'form.markFavorite': 'Mark as favorite',
  'form.generate': 'Generate',

  // TOTP
  'totp.copyCode': 'Copy code',
  'totp.invalid': 'Invalid',

  // Password health / breach check
  'health.title': 'Password health',
  'breach.check': 'Check for breaches',
  'breach.checking': 'Checking…',
  'breach.found': 'Found in {count} known breaches — change it.',
  'breach.notFound': 'Not found in known breaches.',
  'breach.unavailable': 'Breach check unavailable (offline?)',

  // Strength labels
  'strength.veryWeak': 'very weak',
  'strength.weak': 'weak',
  'strength.fair': 'fair',
  'strength.strong': 'strong',
  'strength.veryStrong': 'very strong',
  'strength.bits': '{bits} bits',
  'strength.cracksIn': 'cracks in ~{time}',

  // Password history
  'history.title': 'Password History',
  'history.empty': 'No previous versions.',
  'history.noPassword': '(no password)',

  // Vaults
  'vault.new': 'New Vault',
  'vault.name': 'Vault Name',
  'vault.name.placeholder': 'e.g. Personal, Work',
  'vault.created': 'Vault created',
  'vault.notFound': 'Vault not found',
  'vault.shared': 'Shared',
  'vault.sharedWith': 'Shared with',

  // Teams
  'teams.new': 'New Team',
  'teams.name': 'Team Name',
  'teams.name.placeholder': 'e.g. Engineering, Design',
  'teams.members': 'Members',
  'teams.addMember': 'Add Member',
  'teams.memberEmail.placeholder': 'member@example.com',
  'teams.vaults': 'Team Vaults',
  'teams.createVault': 'Create Vault',
  'teams.vault.new': 'New Team Vault',
  'teams.vault.name.placeholder': 'e.g. Shared Passwords',
  'teams.noMembers': 'No members',
  'teams.noVaults': 'No vaults',
  'teams.promote': 'Promote to admin',
  'teams.demote': 'Demote to member',
  'teams.role.admin': 'Admin',
  'teams.role.member': 'Member',
  'teams.role.owner': 'Owner',
  'teams.role.pending': 'Pending',
  'teams.removeMember': 'Remove member',
  'teams.removeConfirm': 'Remove this member?',
  'teams.notFound': 'Team not found',

  // Import / export
  'import.title': 'Import from 1Password',
  'import.description': 'Select a .csv or .1pif file exported from 1Password.',
  'import.chooseFile': 'Choose file...',
  'import.noItems': 'No items found in file.',
  'import.found': 'Found {count} item(s) — Format: {format}',
  'import.start': 'Import',
  'import.importing': 'Importing...',
  'import.progress': '{done} of {total} items processed...',
  'import.complete': 'Import Complete',
  'import.summary': '{imported} of {total} item(s) imported successfully.',
  'import.errors': '{count} error(s).',
  'import.failed': 'Import failed: {error}',
  'export.title': 'Export',

  // Command palette
  'cmd.placeholder': 'Search items or type a command…',
  'cmd.indexing': 'Indexing your vaults…',
  'cmd.noMatches': 'No matches',
  'cmd.navigate': 'navigate',
  'cmd.open': 'open',
  'cmd.close': 'close',
  'cmd.action': 'action',
  'cmd.toggleTheme': 'Toggle dark mode',
  'search.global.placeholder': 'Search all vaults…',

  // Watchtower (security dashboard)
  'watchtower.title': 'Security Dashboard',
  'watchtower.scanning': 'Scanning your vaults…',
  'watchtower.summary': 'Scanned {logins} logins across {vaults} vaults.',
  'watchtower.allClear': 'No weak, reused, or stale passwords found.',
  'watchtower.weak': 'Weak passwords',
  'watchtower.weak.note': 'Easy to guess — strengthen these.',
  'watchtower.reused': 'Reused passwords',
  'watchtower.reused.note': 'The same password protects multiple items.',
  'watchtower.aging': 'Aging passwords',
  'watchtower.aging.note': 'Unchanged for over a year.',
  'watchtower.breaches': 'Breached passwords',
  'watchtower.breaches.note': 'Seen in known data breaches — change now.',
  'watchtower.breaches.checking': 'Checking Have I Been Pwned…',
  'watchtower.breaches.none': 'No passwords found in known breaches.',
  'watchtower.breaches.unavailable': 'Breach check unavailable (offline).',
  'watchtower.breaches.count': 'in {count} breaches',
  'watchtower.duplicates': 'Duplicate items',
  'watchtower.duplicates.note': 'Multiple items with the same title, username and site.',

  // Password generator
  'generator.title': 'Password Generator',
  'generator.regenerate': 'Regenerate',
  'generator.mode.password': 'Password',
  'generator.mode.passphrase': 'Passphrase',
  'generator.length': 'Length',
  'generator.words': 'Words',
  'generator.noAmbiguous': 'No ambiguous characters',
  'generator.capitalize': 'Capitalize',
  'generator.addNumber': 'Add number',
  'generator.use': 'Use password',

  // One-time share links
  'share.title': 'Share item',
  'share.create': 'Create link',
  'share.expires': 'Expires',
  'share.copy': 'Copy link',
  'share.oneUse': 'One-time use',
  'share.revoked': 'Link revoked',
  'share.open.title': 'Shared item',
  'share.open.gone': 'This link has expired or has already been used.',

  // Toasts
  'toast.copied': 'Copied',
  'toast.saved': 'Saved',
  'toast.copyFailed': 'Copy failed',
  'toast.loggedIn': 'Logged in',
  'toast.loginFailed': 'Login failed: {error}',
  'toast.accountCreated': 'Account created!',
  'toast.unlocked': 'Unlocked',
  'toast.wrongMasterPassword': 'Wrong master password',
  'toast.fillAllFields': 'Fill all fields',
  'toast.passwordsMismatch': 'Passwords do not match',
  'toast.passwordTooShort': 'Password must be at least 8 characters',
  'toast.enterMasterPassword': 'Enter your master password',
  'toast.enterName': 'Enter a name',
  'toast.enterTitle': 'Enter a title',
  'toast.enterTeamName': 'Enter a team name',
  'toast.enterEmail': 'Enter an email',
  'toast.selectVaultFirst': 'Select a vault first',
  'toast.itemSaved': 'Item saved',
  'toast.itemUpdated': 'Item updated',
  'toast.itemDeleted': 'Item deleted',
  'toast.itemNotFound': 'Item not found',
  'toast.deleteConfirm': 'Delete this item? This cannot be undone.',
  'toast.favoriteAdded': 'Added to favorites',
  'toast.favoriteRemoved': 'Removed from favorites',
  'toast.teamCreated': 'Team created',
  'toast.teamVaultCreated': 'Team vault created',
  'toast.memberAdded': 'Member added',
  'toast.memberInvited': 'Member invited (pending encryption setup)',
  'toast.memberRemoved': 'Member removed',
  'toast.promoted': 'Promoted to admin',
  'toast.demoted': 'Demoted to member',
  'toast.passwordResetSuccess': 'Password reset successful!',
  'toast.recoveryFailed': 'Recovery failed: {error}',
  'toast.invalidRecoveryKey': 'Invalid recovery key',
  'toast.encryptionSetup': 'Encryption set up successfully',
  'toast.setupFailed': 'Setup failed: {error}',

  // Onboarding — welcome + first-steps checklist
  'onboarding.title': 'First steps',
  'onboarding.progress': '{done} of {total}',
  'onboarding.dismiss': 'Hide guide',
  'onboarding.complete': 'All set. You know the basics.',
  'onboarding.step.vault': 'Create your first vault',
  'onboarding.step.item': 'Save your first password',
  'onboarding.step.generator': 'Try the generator',
  'onboarding.step.extension': 'Install the browser extension',
  'onboarding.step.team': 'Create a team and share',
  'onboarding.welcome.title': 'Welcome',
  'onboarding.welcome.intro': 'Three things before you start:',
  'onboarding.welcome.zk': 'Everything is encrypted on your device. Neither the server nor its admins can read your data.',
  'onboarding.welcome.vaults': 'Your passwords live in vaults. You can share them with teams without breaking encryption.',
  'onboarding.welcome.guide': 'The first-steps guide in the sidebar walks you through the basics.',
  'onboarding.welcome.start': 'Create my first vault',
  'onboarding.welcome.skip': 'Explore on my own',
};

const fr = {
  // App / global
  'app.name': 'Vault Internal',
  'app.tagline': 'Gestionnaire de mots de passe à connaissance nulle.',
  'app.zeroKnowledge': 'Vos mots de passe ne quittent jamais votre appareil sans être chiffrés.',
  'version.running': 'Version {v}',
  'settings.title': 'Paramètres',
  'settings.language': 'Langue',
  'settings.theme': 'Thème',
  'settings.global': 'Réglages globaux',
  'settings.defaultTheme': 'Thème par défaut',
  'locale.es': 'Español',
  'locale.en': 'English',
  'locale.fr': 'Français',

  // Auth — login / signup
  'auth.email': 'E-mail',
  'auth.email.placeholder': 'vous@exemple.com',
  'auth.masterPassword': 'Mot de passe maître',
  'auth.masterPassword.placeholder': 'Votre mot de passe maître',
  'auth.login': 'Se connecter',
  'auth.noAccount': "Vous n'avez pas de compte ?",
  'auth.signup': "S'inscrire",
  'auth.forgotPassword': 'Mot de passe oublié ?',
  'auth.signup.title': 'Créer un compte',
  'auth.signup.hint': 'Votre mot de passe maître sert à dériver les clés de chiffrement localement. Nous ne le voyons jamais.',
  'auth.signup.passwordPlaceholder': 'Choisissez un mot de passe fort',
  'auth.confirmPassword': 'Confirmer le mot de passe',
  'auth.confirmPassword.placeholder': 'Confirmez le mot de passe',
  'auth.haveAccount': 'Vous avez déjà un compte ?',
  'auth.unlock': 'Déverrouiller',
  'auth.iap.unlockHint': 'Authentifié via Google IAP. Saisissez votre mot de passe maître pour déverrouiller votre coffre.',
  'auth.iap.setupTitle': 'Configurer le chiffrement',
  'auth.iap.setupHint': 'Authentifié via Google IAP. Créez un mot de passe maître pour chiffrer vos données. Nous ne le voyons jamais.',

  // Recovery key screen (after signup / recovery)
  'recovery.title': 'Enregistrez votre clé de récupération',
  'recovery.hint': "Cette clé vous permet de récupérer votre compte si vous oubliez votre mot de passe maître. Conservez-la en lieu sûr : elle ne sera affichée qu'une seule fois.",
  'recovery.copy': 'Copier dans le presse-papiers',
  'recovery.saved': "J'ai enregistré cette clé de récupération",
  'recovery.continue': 'Continuer',

  // Account recovery (forgot password)
  'recover.title': 'Récupération de compte',
  'recover.hint': "Saisissez votre e-mail, votre clé de récupération et un nouveau mot de passe maître pour retrouver l'accès.",
  'recover.key': 'Clé de récupération',
  'recover.key.placeholder': 'Collez votre clé de récupération',
  'recover.newPassword': 'Nouveau mot de passe maître',
  'recover.newPassword.placeholder': 'Choisissez un nouveau mot de passe',
  'recover.confirm': 'Confirmer le nouveau mot de passe',
  'recover.confirm.placeholder': 'Confirmez le nouveau mot de passe',
  'recover.submit': 'Réinitialiser le mot de passe',
  'recover.backToLogin': 'Retour à la connexion',

  // Lock screen
  'lock.title': 'Coffre verrouillé',
  'lock.hint': 'Verrouillé pour votre sécurité. Saisissez votre mot de passe maître pour déverrouiller.',
  'lock.logoutInstead': 'Se déconnecter plutôt',

  // Sidebar
  'sidebar.vaults': 'Coffres',
  'sidebar.newVault': '+ Nouveau coffre',
  'sidebar.teams': 'Équipes',
  'sidebar.newTeam': '+ Nouvelle équipe',
  'sidebar.tools': 'Outils',
  'sidebar.watchtower': 'Tableau de sécurité',
  'sidebar.generator': 'Générateur de mots de passe',
  'sidebar.quickSearch': 'Recherche rapide',
  'sidebar.darkMode': 'Mode sombre',
  'sidebar.lightMode': 'Mode clair',
  'sidebar.lockVault': 'Verrouiller le coffre',
  'sidebar.logout': 'Se déconnecter',

  // Item list
  'items.search.placeholder': 'Rechercher des éléments...',
  'items.empty': "Aucun élément pour l'instant",
  'items.new': '+ Nouvel élément',
  'items.import': 'Importer',
  'items.selectPrompt': 'Sélectionnez un élément pour voir les détails',
  'items.untitled': 'Sans titre',
  'items.favorites': 'Favoris',
  'items.favorite': 'Favori',
  'items.hasTotp': 'Avec TOTP',
  'items.lastEdited': 'Modifié par {name} {when}',
  'items.attachments': 'Pièces jointes',
  'items.attachments.add': 'Ajouter une pièce jointe',
  'items.attachments.tooBig': 'Fichier trop volumineux (max 2 Mo)',
  'items.customFields': 'Champs personnalisés',
  'items.customFields.add': 'Ajouter un champ',
  'items.customFields.label': 'Libellé',
  'items.customFields.value': 'Valeur',
  'items.icon.change': "Changer l'icône",

  // Item types
  'type.login': 'Identifiant',
  'type.card': 'Carte bancaire',
  'type.note': 'Note sécurisée',
  'type.identity': 'Identité',

  // Common actions
  'actions.copy': 'Copier',
  'actions.show': 'Afficher',
  'actions.hide': 'Masquer',
  'actions.edit': 'Modifier',
  'actions.delete': 'Supprimer',
  'actions.close': 'Fermer',
  'actions.cancel': 'Annuler',
  'actions.save': 'Enregistrer',
  'actions.create': 'Créer',
  'actions.add': 'Ajouter',
  'actions.done': 'Terminé',
  'detail.title': 'Détails',

  // Fields (form labels + detail rows)
  'fields.title': 'Titre',
  'fields.title.placeholder': 'ex. GitHub, Gmail',
  'fields.username': "Nom d'utilisateur",
  'fields.usernameOrEmail': "Nom d'utilisateur / E-mail",
  'fields.password': 'Mot de passe',
  'fields.website': 'Site web',
  'fields.url': 'URL',
  'fields.totp': 'Mot de passe à usage unique',
  'fields.totpSecret': 'Secret TOTP (mot de passe à usage unique)',
  'fields.totpSecret.placeholder': 'Secret Base32, ex. JBSWY3DPEHPK3PXP',
  'fields.notes': 'Notes',
  'fields.notes.placeholder': 'Notes facultatives',
  'fields.tags': 'Étiquettes',
  'fields.tags.hint': '(séparées par des virgules)',
  'fields.tags.placeholder': 'travail, social, finances',
  'fields.email': 'E-mail',
  'fields.cardholder': 'Titulaire de la carte',
  'fields.cardNumber': 'Numéro de carte',
  'fields.cardBrand': 'Marque',
  'fields.cardExpiry': 'Expire',
  'fields.cvv': 'CVV',
  'fields.pin': 'PIN',
  'fields.fullName': 'Nom complet',
  'fields.phone': 'Téléphone',
  'fields.address': 'Adresse',
  'fields.company': 'Société',

  // Item form
  'form.newItem': 'Nouvel élément',
  'form.editItem': "Modifier l'élément",
  'form.markFavorite': 'Marquer comme favori',
  'form.generate': 'Générer',

  // TOTP
  'totp.copyCode': 'Copier le code',
  'totp.invalid': 'Non valide',

  // Password health / breach check
  'health.title': 'Santé du mot de passe',
  'breach.check': 'Vérifier les fuites',
  'breach.checking': 'Vérification…',
  'breach.found': 'Trouvé dans {count} fuites connues — changez-le.',
  'breach.notFound': 'Absent des fuites connues.',
  'breach.unavailable': 'Vérification des fuites indisponible (hors ligne ?)',

  // Strength labels
  'strength.veryWeak': 'très faible',
  'strength.weak': 'faible',
  'strength.fair': 'moyen',
  'strength.strong': 'fort',
  'strength.veryStrong': 'très fort',
  'strength.bits': '{bits} bits',
  'strength.cracksIn': 'craqué en ~{time}',

  // Password history
  'history.title': 'Historique des mots de passe',
  'history.empty': 'Aucune version antérieure.',
  'history.noPassword': '(aucun mot de passe)',

  // Vaults
  'vault.new': 'Nouveau coffre',
  'vault.name': 'Nom du coffre',
  'vault.name.placeholder': 'ex. Personnel, Travail',
  'vault.created': 'Coffre créé',
  'vault.notFound': 'Coffre introuvable',
  'vault.shared': 'Partagé',
  'vault.sharedWith': 'Partagé avec',

  // Teams
  'teams.new': 'Nouvelle équipe',
  'teams.name': "Nom de l'équipe",
  'teams.name.placeholder': 'ex. Ingénierie, Design',
  'teams.members': 'Membres',
  'teams.addMember': 'Ajouter un membre',
  'teams.memberEmail.placeholder': 'membre@exemple.com',
  'teams.vaults': "Coffres de l'équipe",
  'teams.createVault': 'Créer un coffre',
  'teams.vault.new': "Nouveau coffre d'équipe",
  'teams.vault.name.placeholder': 'ex. Mots de passe partagés',
  'teams.noMembers': 'Aucun membre',
  'teams.noVaults': 'Aucun coffre',
  'teams.promote': 'Promouvoir administrateur',
  'teams.demote': 'Rétrograder en membre',
  'teams.role.admin': 'Administrateur',
  'teams.role.member': 'Membre',
  'teams.role.owner': 'Propriétaire',
  'teams.role.pending': 'En attente',
  'teams.removeMember': 'Retirer le membre',
  'teams.removeConfirm': 'Retirer ce membre ?',
  'teams.notFound': 'Équipe introuvable',

  // Import / export
  'import.title': 'Importer depuis 1Password',
  'import.description': 'Sélectionnez un fichier .csv ou .1pif exporté depuis 1Password.',
  'import.chooseFile': 'Choisir un fichier...',
  'import.noItems': 'Aucun élément trouvé dans le fichier.',
  'import.found': '{count} éléments trouvés — Format : {format}',
  'import.start': 'Importer',
  'import.importing': 'Importation...',
  'import.progress': '{done} sur {total} éléments traités...',
  'import.complete': 'Importation terminée',
  'import.summary': '{imported} sur {total} éléments importés avec succès.',
  'import.errors': '{count} erreurs.',
  'import.failed': "Échec de l'importation : {error}",
  'export.title': 'Exporter',

  // Command palette
  'cmd.placeholder': 'Recherchez des éléments ou tapez une commande…',
  'cmd.indexing': 'Indexation de vos coffres…',
  'cmd.noMatches': 'Aucun résultat',
  'cmd.navigate': 'naviguer',
  'cmd.open': 'ouvrir',
  'cmd.close': 'fermer',
  'cmd.action': 'action',
  'cmd.toggleTheme': 'Basculer le mode sombre',
  'search.global.placeholder': 'Rechercher dans tous les coffres…',

  // Watchtower (security dashboard)
  'watchtower.title': 'Tableau de sécurité',
  'watchtower.scanning': 'Analyse de vos coffres…',
  'watchtower.summary': '{logins} identifiants analysés dans {vaults} coffres.',
  'watchtower.allClear': 'Aucun mot de passe faible, réutilisé ou ancien trouvé.',
  'watchtower.weak': 'Mots de passe faibles',
  'watchtower.weak.note': 'Faciles à deviner — renforcez-les.',
  'watchtower.reused': 'Mots de passe réutilisés',
  'watchtower.reused.note': 'Le même mot de passe protège plusieurs éléments.',
  'watchtower.aging': 'Mots de passe anciens',
  'watchtower.aging.note': "Inchangés depuis plus d'un an.",
  'watchtower.breaches': 'Mots de passe compromis',
  'watchtower.breaches.note': 'Présents dans des fuites de données connues — changez-les maintenant.',
  'watchtower.breaches.checking': 'Vérification sur Have I Been Pwned…',
  'watchtower.breaches.none': 'Aucun mot de passe trouvé dans des fuites connues.',
  'watchtower.breaches.unavailable': 'Vérification des fuites indisponible (hors ligne).',
  'watchtower.breaches.count': 'dans {count} fuites',
  'watchtower.duplicates': 'Éléments en double',
  'watchtower.duplicates.note': 'Plusieurs éléments avec le même titre, identifiant et site.',

  // Password generator
  'generator.title': 'Générateur de mots de passe',
  'generator.regenerate': 'Régénérer',
  'generator.mode.password': 'Mot de passe',
  'generator.mode.passphrase': 'Phrase de passe',
  'generator.length': 'Longueur',
  'generator.words': 'Mots',
  'generator.noAmbiguous': 'Sans caractères ambigus',
  'generator.capitalize': 'Majuscule initiale',
  'generator.addNumber': 'Ajouter un chiffre',
  'generator.use': 'Utiliser le mot de passe',

  // One-time share links
  'share.title': "Partager l'élément",
  'share.create': 'Créer le lien',
  'share.expires': 'Expire',
  'share.copy': 'Copier le lien',
  'share.oneUse': 'Usage unique',
  'share.revoked': 'Lien révoqué',
  'share.open.title': 'Élément partagé',
  'share.open.gone': 'Ce lien a expiré ou a déjà été utilisé.',

  // Toasts
  'toast.copied': 'Copié',
  'toast.saved': 'Enregistré',
  'toast.copyFailed': 'Échec de la copie',
  'toast.loggedIn': 'Connecté',
  'toast.loginFailed': 'Échec de la connexion : {error}',
  'toast.accountCreated': 'Compte créé !',
  'toast.unlocked': 'Déverrouillé',
  'toast.wrongMasterPassword': 'Mot de passe maître incorrect',
  'toast.fillAllFields': 'Remplissez tous les champs',
  'toast.passwordsMismatch': 'Les mots de passe ne correspondent pas',
  'toast.passwordTooShort': 'Le mot de passe doit comporter au moins 8 caractères',
  'toast.enterMasterPassword': 'Saisissez votre mot de passe maître',
  'toast.enterName': 'Saisissez un nom',
  'toast.enterTitle': 'Saisissez un titre',
  'toast.enterTeamName': "Saisissez un nom d'équipe",
  'toast.enterEmail': 'Saisissez un e-mail',
  'toast.selectVaultFirst': "Sélectionnez d'abord un coffre",
  'toast.itemSaved': 'Élément enregistré',
  'toast.itemUpdated': 'Élément mis à jour',
  'toast.itemDeleted': 'Élément supprimé',
  'toast.itemNotFound': 'Élément introuvable',
  'toast.deleteConfirm': 'Supprimer cet élément ? Cette action est irréversible.',
  'toast.favoriteAdded': 'Ajouté aux favoris',
  'toast.favoriteRemoved': 'Retiré des favoris',
  'toast.teamCreated': 'Équipe créée',
  'toast.teamVaultCreated': "Coffre d'équipe créé",
  'toast.memberAdded': 'Membre ajouté',
  'toast.memberInvited': 'Membre invité (configuration du chiffrement en attente)',
  'toast.memberRemoved': 'Membre retiré',
  'toast.promoted': 'Promu administrateur',
  'toast.demoted': 'Rétrogradé en membre',
  'toast.passwordResetSuccess': 'Mot de passe réinitialisé !',
  'toast.recoveryFailed': 'Échec de la récupération : {error}',
  'toast.invalidRecoveryKey': 'Clé de récupération non valide',
  'toast.encryptionSetup': 'Chiffrement configuré avec succès',
  'toast.setupFailed': 'Échec de la configuration : {error}',

  // Onboarding — welcome + first-steps checklist
  'onboarding.title': 'Premiers pas',
  'onboarding.progress': '{done} sur {total}',
  'onboarding.dismiss': 'Masquer le guide',
  'onboarding.complete': 'Tout est prêt. Vous maîtrisez les bases.',
  'onboarding.step.vault': 'Créez votre premier coffre-fort',
  'onboarding.step.item': 'Enregistrez votre premier mot de passe',
  'onboarding.step.generator': 'Essayez le générateur',
  'onboarding.step.extension': 'Installez l\'extension de navigateur',
  'onboarding.step.team': 'Créez une équipe et partagez',
  'onboarding.welcome.title': 'Bienvenue',
  'onboarding.welcome.intro': 'Trois choses avant de commencer :',
  'onboarding.welcome.zk': 'Tout est chiffré sur votre appareil. Ni le serveur ni ses administrateurs ne peuvent lire vos données.',
  'onboarding.welcome.vaults': 'Vos mots de passe vivent dans des coffres-forts. Partagez-les avec des équipes sans casser le chiffrement.',
  'onboarding.welcome.guide': 'Le guide des premiers pas du menu latéral vous accompagne pour les bases.',
  'onboarding.welcome.start': 'Créer mon premier coffre-fort',
  'onboarding.welcome.skip': 'Explorer par moi-même',
};

// Exposed for tests and tooling (key-set parity checks, i18n-keys.md generation).
// Not part of the UI contract — the UI uses t()/applyI18n().
export const MESSAGES = { es, en, fr };

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

let currentLocale = DEFAULT_LOCALE;

function safeLocalStorage() {
  try {
    if (typeof localStorage !== 'undefined' && localStorage) return localStorage;
  } catch { /* storage access can throw (privacy mode) */ }
  return null;
}

/**
 * Resolve and set the active locale:
 * 1. localStorage 'mp-locale' (if it is a supported locale)
 * 2. navigator.language two-letter prefix match against LOCALES
 * 3. 'es'
 * Returns the resolved locale.
 */
export function initI18n() {
  const store = safeLocalStorage();
  let saved = null;
  try { saved = store ? store.getItem(STORAGE_KEY) : null; } catch { saved = null; }
  if (saved && LOCALES.includes(saved)) {
    currentLocale = saved;
    return currentLocale;
  }

  let navLang = '';
  try {
    if (typeof navigator !== 'undefined' && navigator && navigator.language) {
      navLang = String(navigator.language);
    }
  } catch { navLang = ''; }
  const prefix = navLang.slice(0, 2).toLowerCase();
  currentLocale = LOCALES.includes(prefix) ? prefix : DEFAULT_LOCALE;
  return currentLocale;
}

export function getLocale() {
  return currentLocale;
}

/**
 * Set the active locale and persist it to localStorage.
 * Unsupported locales are ignored. No reload logic here — callers decide
 * whether to re-render / applyI18n().
 */
export function setLocale(locale) {
  if (!LOCALES.includes(locale)) return currentLocale;
  currentLocale = locale;
  const store = safeLocalStorage();
  try { if (store) store.setItem(STORAGE_KEY, locale); } catch { /* best effort */ }
  return currentLocale;
}

function interpolate(str, vars) {
  if (!vars || typeof vars !== 'object') return str;
  return str.replace(/\{(\w+)\}/g, (match, name) =>
    Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match);
}

/**
 * Translate a key in the active locale.
 * Fallback chain: active locale -> 'es' -> the key itself.
 * `{name}` placeholders are interpolated from `vars`.
 */
export function t(key, vars = {}) {
  const active = MESSAGES[currentLocale] || MESSAGES[DEFAULT_LOCALE];
  let str = active[key];
  if (str === undefined) str = MESSAGES[DEFAULT_LOCALE][key];
  if (str === undefined) return interpolate(String(key), vars);
  return interpolate(str, vars);
}

/**
 * Apply translations to the DOM subtree under `root`:
 *   [data-i18n]              -> textContent
 *   [data-i18n-placeholder]  -> placeholder attribute
 *   [data-i18n-title]        -> title attribute
 */
export function applyI18n(root = (typeof document !== 'undefined' ? document : null)) {
  if (!root || typeof root.querySelectorAll !== 'function') return;
  root.querySelectorAll('[data-i18n]').forEach((el) => {
    const key = el.getAttribute('data-i18n');
    if (key) el.textContent = t(key);
  });
  root.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    const key = el.getAttribute('data-i18n-placeholder');
    if (key) el.setAttribute('placeholder', t(key));
  });
  root.querySelectorAll('[data-i18n-title]').forEach((el) => {
    const key = el.getAttribute('data-i18n-title');
    if (key) el.setAttribute('title', t(key));
  });
}
