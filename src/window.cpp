#include "window.hpp"


CheckboxModel::CheckboxModel(QWidget *parent) : QComboBox(parent) {
    //add initialization of model_box in the construction
    model_box = new QStandardItemModel(this);
    model_box->appendRow(makeitem(QString{"packet no."}, 0));
    model_box->appendRow(makeitem(QString{"timestamp"},1));
    model_box->appendRow(makeitem(QString{"mac src"}, 2));
    model_box->appendRow(makeitem(QString{"mac dest"}, 3));
    model_box->appendRow(makeitem(QString{"internet type"}, 4));
    model_box->appendRow(makeitem(QString{"protocol"}, 5));
    model_box->appendRow(makeitem(QString{"ipv4 src"}, 6));
    model_box->appendRow(makeitem(QString{"ipv4 dest"}, 7));
    this->QComboBox::setModel(model_box);
    connect(model_box, &QStandardItemModel::itemChanged, this, &CheckboxModel::itemchangedmodel);
}

QStringList CheckboxModel::returncheckeditems(QStandardItemModel *model) {
    QStringList item_checked;

    for (int i{0}; i < model->rowCount(); i++) {
        auto *item = model->item(i);
        if (item->data(Qt::CheckStateRole) == Qt::Checked) {
            item_checked.append(item->text());
        }
    }
    return item_checked;
}

inline QStandardItem *CheckboxModel::makeitem(const QString &text, int id) {
    auto *newitem = new QStandardItem(text);
    newitem->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);
    newitem->setData(Qt::Checked, Qt::CheckStateRole);
    newitem->setData(id, Qt::UserRole);
    return newitem;
}

void Window::onitemchange(const QStandardItem *item) {
    auto id = item->data(Qt::UserRole);
    if (item->data(Qt::CheckStateRole) == Qt::Unchecked) {
        view->hideColumn(id.toInt());
    }else {
        view->showColumn(id.toInt());
    }
}

Window::Window(QWidget *parent) {
    auto *model_checkbox = new CheckboxModel(this);

    model = new MyModel(this);
    auto *layout = new QVBoxLayout(this);
    view = new QTableView(this);

    layout->addWidget(model_checkbox);
    layout->addWidget(view);
    connect(model, &MyModel::newpacketadded, view, &QTableView::scrollToBottom);
    connect(model_checkbox, &CheckboxModel::itemchangedmodel, this, &Window::onitemchange);

    view->setModel(model);
    view->verticalHeader()->hide();
    resize(1000, 800);
}
