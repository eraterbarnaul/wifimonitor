import sys
from pathlib import Path
from typing import Optional, Tuple

from PyQt5.QtWidgets import QApplication, QFileDialog, QMessageBox

if __package__ in (None, ""):
    package_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(package_root))
    from wifimonitor.controller import WifiMonitorController
    from wifimonitor.ui.main_window import MainWindow
else:
    from .controller import WifiMonitorController
    from .ui.main_window import MainWindow


def _select_storage(default_dir: Path) -> Optional[Tuple[Path, Path]]:
    default_dir.mkdir(parents=True, exist_ok=True)
    db_suggest = default_dir / "wifimonitor.db"
    db_path_str, _ = QFileDialog.getSaveFileName(
        None,
        "Выберите или создайте базу данных",
        str(db_suggest),
        "SQLite DB (*.db);;Все файлы (*)",
    )
    if not db_path_str:
        return None
    db_path = Path(db_path_str).expanduser().resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    capture_dir_str = QFileDialog.getExistingDirectory(
        None,
        "Выберите каталог для сохранения захватов",
        str(db_path.parent),
    )
    if capture_dir_str:
        capture_dir = Path(capture_dir_str).expanduser().resolve()
    else:
        capture_dir = db_path.parent / "captures"
    capture_dir.mkdir(parents=True, exist_ok=True)
    return db_path, capture_dir


def main() -> None:
    app = QApplication(sys.argv)
    theme_path = Path(__file__).resolve().parent / "ui" / "styles" / "cyberpunk.qss"
    if theme_path.exists():
        with theme_path.open("r", encoding="utf-8") as fh:
            app.setStyleSheet(fh.read())
    storage = _select_storage(Path.home() / ".wifimonitor")
    if storage is None:
        QMessageBox.information(None, "Wifimonitor", "Запуск отменён: база данных не выбрана.")
        sys.exit(0)
    db_path, capture_dir = storage
    controller = WifiMonitorController(db_path=db_path, capture_dir=capture_dir)
    window = MainWindow(controller, db_path=db_path, capture_dir=capture_dir)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
