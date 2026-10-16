# Bug tracker Sebach Plus

Worker `sebachplus-bugtracker`, collegato a git con root directory `bugtracker`.
Ogni push che tocca `bugtracker/` fa il deploy automatico.

Secret richiesti nel Worker: `DASH_PASSWORD`/`DEFAULT_PASSWORD` (vedi impostazioni), D1 binding `DB` (`sebachplus-bugs`).
