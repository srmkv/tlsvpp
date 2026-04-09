Исправления v2:
- убраны undefined systemUser / osType / osVersion в клиенте
- renderSelfState теперь корректно берет:
  - SystemUser из self или system.DetectSystemUser()
  - OSType / OSVersion из self или system.DetectOSInfo()
- клиент отправляет category в apps/report
