#include "main_window.hpp"

#include "disasm_model.hpp"
#include "fathom/engine.hpp"
#include "fathom/util.hpp"
#include "graph_view.hpp"
#include "hex_model.hpp"
#include "theme.hpp"

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QDir>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFileDialog>
#include <QFont>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QInputDialog>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMouseEvent>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QShortcut>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTableView>
#include <QVBoxLayout>
#include <QtConcurrent>

#include <algorithm>
#include <utility>

namespace fathom {
namespace {

QLabel* heading(const QString& text, QWidget* parent) {
    auto* label = new QLabel(text, parent);
    label->setStyleSheet(QStringLiteral("color: #8ea0b5; background: transparent; border: none;"));
    return label;
}

QTableView* code_table(QAbstractItemModel* model, QWidget* parent) {
    auto* table = new QTableView(parent);
    table->setModel(model);
    table->setFont(theme::code_font());
    table->setShowGrid(false);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->setVisible(false);
    table->verticalHeader()->setDefaultSectionSize(22);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setHighlightSections(false);
    table->setWordWrap(false);
    table->setAlternatingRowColors(false);
    return table;
}

QString shorten(std::string_view text, int limit) {
    QString out = QString::fromStdString(std::string(text));
    if (out.size() > limit) {
        out.truncate(limit);
        out += QStringLiteral("…");
    }
    return out;
}

}  // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("Fathom"));
    setAcceptDrops(true);
    build_ui();
    statusBar()->showMessage(QStringLiteral("Open a binary"));
}

void MainWindow::build_ui() {
    auto* file_menu = menuBar()->addMenu(QStringLiteral("File"));
    auto* open = file_menu->addAction(QStringLiteral("Open…"));
    open->setShortcut(QKeySequence::Open);
    connect(open, &QAction::triggered, this, &MainWindow::open_dialog);
    file_menu->addSeparator();
    auto* quit = file_menu->addAction(QStringLiteral("Quit"));
    quit->setShortcut(QKeySequence::Quit);
    connect(quit, &QAction::triggered, this, &QWidget::close);

    auto* view_menu = menuBar()->addMenu(QStringLiteral("View"));
    auto* group = new QActionGroup(this);
    hex_action_ = view_menu->addAction(QStringLiteral("Hex"));
    graph_action_ = view_menu->addAction(QStringLiteral("Graph"));
    hex_action_->setCheckable(true);
    graph_action_->setCheckable(true);
    hex_action_->setChecked(true);
    group->addAction(hex_action_);
    group->addAction(graph_action_);
    connect(hex_action_, &QAction::triggered, this, [this] { set_lower(LowerView::Hex); });
    connect(graph_action_, &QAction::triggered, this, [this] { set_lower(LowerView::Graph); });

    auto* navigate = menuBar()->addMenu(QStringLiteral("Navigate"));
    auto* go = navigate->addAction(QStringLiteral("Go to address…"));
    go->setShortcut(QKeySequence(Qt::CTRL | Qt::Key_G));
    connect(go, &QAction::triggered, this, &MainWindow::go_to_address);

    auto* sidebar = new QWidget(this);
    auto* side_layout = new QVBoxLayout(sidebar);
    side_layout->setContentsMargins(8, 8, 8, 8);
    side_layout->setSpacing(6);
    filter_ = new QLineEdit(sidebar);
    filter_->setPlaceholderText(QStringLiteral("Filter functions and strings"));
    filter_->setClearButtonEnabled(true);
    side_layout->addWidget(filter_);
    connect(filter_, &QLineEdit::textChanged, this, [this](const QString& text) {
        if (updating_ || !bench_.has_program()) {
            return;
        }
        bench_.set_filter(text.toStdString());
        refresh_lists();
    });

    side_layout->addWidget(heading(QStringLiteral("Functions"), sidebar));
    functions_ = new QListWidget(sidebar);
    functions_->setFont(theme::code_font(11));
    side_layout->addWidget(functions_, 3);
    side_layout->addWidget(heading(QStringLiteral("Strings"), sidebar));
    strings_ = new QListWidget(sidebar);
    strings_->setFont(theme::code_font(11));
    side_layout->addWidget(strings_, 2);
    side_layout->addWidget(heading(QStringLiteral("Triage"), sidebar));
    triage_ = new QListWidget(sidebar);
    side_layout->addWidget(triage_, 1);
    side_layout->addWidget(heading(QStringLiteral("Cross-references"), sidebar));
    xrefs_ = new QListWidget(sidebar);
    xrefs_->setFont(theme::code_font(11));
    side_layout->addWidget(xrefs_, 1);

    auto choose_from = [this](QListWidgetItem* item) {
        if (updating_ || item == nullptr || !item->data(Qt::UserRole).isValid()) {
            return;
        }
        choose(item->data(Qt::UserRole).toULongLong());
    };
    connect(functions_, &QListWidget::itemClicked, this, choose_from);
    connect(strings_, &QListWidget::itemClicked, this, choose_from);
    connect(xrefs_, &QListWidget::itemClicked, this, choose_from);

    disasm_model_ = new DisasmModel(this);
    disasm_ = code_table(disasm_model_, this);
    disasm_->setSelectionBehavior(QAbstractItemView::SelectRows);
    disasm_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    disasm_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    connect(disasm_, &QTableView::clicked, this, [this](const QModelIndex& index) {
        if (!updating_) {
            choose(disasm_model_->address_at(index.row()));
        }
    });
    connect(disasm_, &QTableView::doubleClicked, this, [this](const QModelIndex& index) {
        if (!bench_.has_program()) {
            return;
        }
        const uint64_t address = disasm_model_->address_at(index.row());
        if (const Instruction* insn = find_insn(bench_.program(), address)) {
            if (insn->target) {
                choose(*insn->target);
            }
        }
    });

    listing_ = new QPlainTextEdit(this);
    listing_->setReadOnly(true);
    listing_->setFont(theme::code_font());
    listing_->setLineWrapMode(QPlainTextEdit::WidgetWidth);
    listing_->setPlaceholderText(QStringLiteral("Open a binary to see the structural listing."));
    listing_->viewport()->installEventFilter(this);


    hex_model_ = new HexModel(this);
    hex_ = code_table(hex_model_, this);
    hex_->setSelectionBehavior(QAbstractItemView::SelectItems);
    hex_->horizontalHeader()->setStretchLastSection(true);
    hex_->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    connect(hex_, &QTableView::clicked, this, [this](const QModelIndex& index) {
        if (updating_) {
            return;
        }
        if (const auto address = hex_model_->address_at(index)) {
            choose(*address);
        }
    });

    graph_ = new GraphView(this);
    connect(graph_, &GraphView::addressChosen, this, [this](quint64 address) { choose(address); });

    lower_ = new QStackedWidget(this);
    lower_->addWidget(hex_);
    lower_->addWidget(graph_);

    auto* upper = new QSplitter(Qt::Horizontal, this);
    upper->addWidget(disasm_);
    upper->addWidget(listing_);
    upper->setStretchFactor(0, 1);
    upper->setStretchFactor(1, 1);

    auto* views = new QSplitter(Qt::Vertical, this);
    views->addWidget(upper);
    views->addWidget(lower_);
    views->setStretchFactor(0, 3);
    views->setStretchFactor(1, 2);

    auto* central = new QSplitter(Qt::Horizontal, this);
    central->addWidget(sidebar);
    central->addWidget(views);
    central->setStretchFactor(0, 0);
    central->setStretchFactor(1, 1);
    central->setSizes({300, 1000});
    setCentralWidget(central);

    status_arch_ = new QLabel(this);
    status_cursor_ = new QLabel(this);
    status_path_ = new QLabel(this);
    for (QLabel* label : {status_arch_, status_cursor_, status_path_}) {
        label->setFont(theme::code_font(11));
        statusBar()->addPermanentWidget(label);
    }
}

void MainWindow::open_dialog() {
    const QString path = QFileDialog::getOpenFileName(this, QStringLiteral("Open binary"), QDir::homePath(),
                                                      QStringLiteral("All files (*)"));
    if (!path.isEmpty()) {
        open_path(path);
    }
}

void MainWindow::open_path(const QString& path) {
    const int ticket = ++ticket_;
    statusBar()->showMessage(QStringLiteral("Loading %1").arg(path));
    QApplication::setOverrideCursor(Qt::WaitCursor);
    auto* watcher = new QFutureWatcher<LoadResult>(this);
    connect(watcher, &QFutureWatcher<LoadResult>::finished, this, [this, watcher, ticket] {
        LoadResult result = watcher->result();
        watcher->deleteLater();
        QApplication::restoreOverrideCursor();
        if (ticket != ticket_) {
            return;
        }
        if (!result.error.empty()) {
            statusBar()->showMessage(QString::fromStdString(result.error));
            QMessageBox::warning(this, QStringLiteral("Fathom"), QString::fromStdString(result.error));
            return;
        }
        bench_.set_program(std::move(result.program));
        shown_function_.reset();
        updating_ = true;
        filter_->clear();
        updating_ = false;
        hex_action_->setChecked(true);
        lower_->setCurrentIndex(0);
        refresh_lists();
        refresh_views(true);
        refresh_status();
        setWindowTitle(QStringLiteral("Fathom — %1").arg(QString::fromStdString(base_name(bench_.program().path))));
        statusBar()->clearMessage();
    });
    watcher->setFuture(QtConcurrent::run([path] {
        LoadResult result;
        try {
            result.program = load_program(path.toStdString());
            analyze(result.program);
        } catch (const Error& error) {
            result.error = error.what();
        } catch (const std::exception& error) {
            result.error = error.what();
        }
        return result;
    }));
}

void MainWindow::go_to_address() {
    if (!bench_.has_program()) {
        return;
    }
    bool ok = false;
    const QString text = QInputDialog::getText(this, QStringLiteral("Go to address"), QStringLiteral("Address"),
                                               QLineEdit::Normal, QString(), &ok);
    if (!ok) {
        return;
    }
    const auto address = parse_address(text.trimmed().toStdString());
    if (!address) {
        statusBar()->showMessage(QStringLiteral("Enter an address such as 0x1000"));
        return;
    }
    choose(*address);
}

void MainWindow::set_lower(LowerView view) {
    bench_.set_lower(view);
    lower_->setCurrentIndex(view == LowerView::Graph ? 1 : 0);
    if (view == LowerView::Graph && bench_.has_program()) {
        graph_->set_blocks(bench_.graph(), bench_.cursor());
    }
}

void MainWindow::choose(uint64_t address) {
    if (!bench_.has_program() || updating_) {
        return;
    }
    const auto before = shown_function();
    bench_.select(address);
    const auto after = shown_function();
    refresh_views(before != after);
    refresh_xrefs();
    if (before != after) {
        updating_ = true;
        for (int i = 0; i < functions_->count(); ++i) {
            QListWidgetItem* item = functions_->item(i);
            if (item->data(Qt::UserRole).isValid() && after && item->data(Qt::UserRole).toULongLong() == *after) {
                functions_->setCurrentRow(i);
                functions_->scrollToItem(item);
                break;
            }
        }
        updating_ = false;
    }
    refresh_status();
}

std::optional<uint64_t> MainWindow::shown_function() const {
    const Function* function = bench_.current_function();
    if (function == nullptr) {
        return std::nullopt;
    }
    return function->address;
}

void MainWindow::fill_list(QListWidget* list, const std::vector<std::pair<uint64_t, QString>>& rows, int cap) {
    list->clear();
    const int shown = std::min(static_cast<int>(rows.size()), cap);
    for (int i = 0; i < shown; ++i) {
        auto* item = new QListWidgetItem(rows[static_cast<size_t>(i)].second, list);
        item->setData(Qt::UserRole, static_cast<qulonglong>(rows[static_cast<size_t>(i)].first));
    }
    if (static_cast<int>(rows.size()) > cap) {
        auto* more = new QListWidgetItem(
            QStringLiteral("%1 more. Filter to narrow the list.").arg(static_cast<int>(rows.size()) - cap), list);
        more->setFlags(Qt::NoItemFlags);
        more->setForeground(theme::kMuted);
    }
}

void MainWindow::refresh_lists() {
    updating_ = true;
    std::vector<std::pair<uint64_t, QString>> functions;
    for (const auto& row : bench_.functions()) {
        functions.emplace_back(row.address, QStringLiteral("%1    %2")
                                                 .arg(QString::fromStdString(row.name),
                                                      QString::fromStdString(hex_addr(row.address))));
    }
    fill_list(functions_, functions, 8000);
    if (const auto current = shown_function()) {
        for (int i = 0; i < functions_->count(); ++i) {
            if (functions_->item(i)->data(Qt::UserRole).toULongLong() == *current) {
                functions_->setCurrentRow(i);
                break;
            }
        }
    }

    std::vector<std::pair<uint64_t, QString>> strings;
    for (const auto& row : bench_.strings()) {
        const QString kind = row.utf16 ? QStringLiteral("utf16") : QStringLiteral("ascii");
        strings.emplace_back(row.address, QStringLiteral("%1    %2    %3")
                                               .arg(QString::fromStdString(hex_addr(row.address)), kind,
                                                    shorten(row.text, 80)));
    }
    fill_list(strings_, strings, 4000);

    triage_->clear();
    for (const auto& row : bench_.triage()) {
        auto* item = new QListWidgetItem(
            QStringLiteral("%1    %2    %3")
                .arg(QString::fromStdString(row.severity), QString::fromStdString(row.category),
                     shorten(row.detail, 120)),
            triage_);
        if (row.severity == "high") {
            item->setForeground(theme::kCopper);
        } else {
            item->setForeground(theme::kMuted);
        }
    }

    refresh_xrefs();
    updating_ = false;
}

void MainWindow::refresh_xrefs() {
    updating_ = true;
    xrefs_->clear();
    for (const auto& row : bench_.xrefs()) {
        auto* item = new QListWidgetItem(
            QStringLiteral("%1    %2").arg(QString::fromStdString(row.kind), QString::fromStdString(hex_addr(row.from))),
            xrefs_);
        item->setData(Qt::UserRole, static_cast<qulonglong>(row.from));
    }
    if (bench_.has_program() && bench_.cursor_known() && xrefs_->count() == 0) {
        auto* none = new QListWidgetItem(QStringLiteral("No cross-references at the cursor"), xrefs_);
        none->setFlags(Qt::NoItemFlags);
        none->setForeground(theme::kMuted);
    }
    updating_ = false;
}

void MainWindow::refresh_views(bool function_changed) {
    if (!bench_.has_program()) {
        return;
    }
    updating_ = true;
    if (function_changed) {
        shown_function_ = shown_function();
        disasm_model_->set_rows(bench_.disassembly());
        const QString listing = QString::fromStdString(bench_.listing());
        if (listing_->toPlainText() != listing) {
            listing_->setPlainText(listing);
        }
        graph_->set_blocks(bench_.graph(), bench_.cursor_known() ? bench_.cursor() : 0);
    } else if (bench_.lower() == LowerView::Graph) {
        graph_->set_cursor(bench_.cursor());
    }
    hex_model_->set_lines(bench_.hex());
    if (bench_.cursor_known()) {
        const int row = disasm_model_->row_for(bench_.cursor());
        if (row >= 0) {
            disasm_->selectRow(row);
            disasm_->scrollTo(disasm_model_->index(row, 0), QAbstractItemView::PositionAtCenter);
        } else {
            disasm_->clearSelection();
        }
        if (const QModelIndex cell = hex_model_->index_for(bench_.cursor()); cell.isValid()) {
            hex_->setCurrentIndex(cell);
            hex_->scrollTo(cell, QAbstractItemView::PositionAtCenter);
        }
        const QString needle = QString::fromStdString(hex_addr(bench_.cursor()) + ":");
        const int mark = listing_->toPlainText().indexOf(needle);
        if (mark >= 0) {
            QTextCursor cursor = listing_->textCursor();
            cursor.setPosition(mark);
            listing_->setTextCursor(cursor);
            listing_->ensureCursorVisible();
        }
    }
    updating_ = false;
}

void MainWindow::refresh_status() {
    if (!bench_.has_program()) {
        status_arch_->clear();
        status_cursor_->clear();
        status_path_->clear();
        return;
    }
    status_arch_->setText(QStringLiteral("%1    %2").arg(QString::fromStdString(bench_.arch_label()),
                                                         QString::fromStdString(bench_.format_label())));
    QString cursor = QStringLiteral("cursor —");
    if (bench_.cursor_known()) {
        cursor = QStringLiteral("cursor %1").arg(QString::fromStdString(hex_addr(bench_.cursor())));
    }
    if (bench_.program().entry_known) {
        cursor += QStringLiteral("    entry %1").arg(QString::fromStdString(hex_addr(bench_.program().entry)));
    }
    if (!bench_.program().notes.empty()) {
        cursor += QStringLiteral("    %1").arg(QString::fromStdString(bench_.program().notes.front()));
    }
    status_cursor_->setText(cursor);
    status_path_->setText(QString::fromStdString(bench_.program().path));
}

bool MainWindow::eventFilter(QObject* watched, QEvent* event) {
    if (watched == listing_->viewport() && event->type() == QEvent::MouseButtonRelease && !updating_) {
        const auto* mouse = static_cast<QMouseEvent*>(event);
        QTextCursor cursor = listing_->cursorForPosition(mouse->pos());
        cursor.select(QTextCursor::LineUnderCursor);
        const QString line = cursor.selectedText();
        const int mark = line.indexOf(QStringLiteral("0x"));
        if (mark >= 0) {
            int end = mark + 2;
            while (end < line.size()) {
                const QChar c = line.at(end);
                if (!c.isDigit() && (c.toLower() < QLatin1Char('a') || c.toLower() > QLatin1Char('f'))) {
                    break;
                }
                ++end;
            }
            if (const auto address = parse_address(line.mid(mark, end - mark).toStdString())) {
                choose(*address);
            }
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void MainWindow::dragEnterEvent(QDragEnterEvent* event) {
    if (event->mimeData()->hasUrls()) {
        event->acceptProposedAction();
    }
}

void MainWindow::dropEvent(QDropEvent* event) {
    const QList<QUrl> urls = event->mimeData()->urls();
    if (!urls.isEmpty()) {
        open_path(urls.front().toLocalFile());
    }
}

}  // namespace fathom
