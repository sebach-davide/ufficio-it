# Bug tracker Sebach Plus

Worker `sebachplus-bugtracker`, collegato a git con root directory `bugtracker`.
Ogni push che tocca `bugtracker/` fa il deploy automatico.

Configurazione richiesta nel Worker:
- secret `DEFAULT_PASSWORD`: password per gli utenti senza password personale
- D1 binding `DB`: database `sebachplus-bugs`
