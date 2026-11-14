# Záznam o incidente INC-2026-884 – Interná skladová aplikácia

Dátum: 2026-11-06
Autor: IT podpora, Modelová firma Delta
Metadáta: Fiktívny dokument pre školský experiment.

Dňa 6. novembra 2026 o 08:45 nahlásil skladový personál nedostupnosť internej skladovej aplikácie Delta Sklad verzie 2.4. Používatelia v skladoch Žilina a Trnava nemohli synchronizovať ručné čítačky čiarových kódov so serverom, čo spôsobilo dočasné zastavenie príjmu tovaru.

Diagnostika tímu IT podpory preukázala zaplnenie diskového priestoru na aplikačnom serveri spôsobené nadmerným ukladaním dočasných ladiacich protokolov. Incident bol klasifikovaný s prioritou P2. Administrátori vykonali manuálne prečistenie archívnych logov, uvoľnili 45 gigabajtov priestoru a upravili pravidlo automatickej rotácie súborov. Služba bola plne obnovená o 09:35. Celkový výpadok trval 50 minút bez straty transakčných dát. Na zabránenie opakovaniu problému bol nastavený automatický monitorovací limit na úroveň 80 percent kapacity disku.
