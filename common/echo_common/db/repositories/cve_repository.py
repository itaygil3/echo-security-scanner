from echo_common.db.repositories.base_repository import BaseRepository
from echo_common.db.tables import cves
from echo_common.models import CVE


class CVERepository(BaseRepository[CVE]):
    table = cves
    model = CVE
