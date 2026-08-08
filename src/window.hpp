//
// Created by lhbdawn on 02-08-2026.
//

#pragma once
#include <QWidget>
#include "mymodel.hpp"
#include <QTableView>
#include <QBoxLayout>
#include <QHeaderView>
#include <QComboBox>
#include <QCheckBox>
#include <QStandardItemModel>
#include <QStandardItem>
#include <QStringList>

class Window : public QWidget
{
inline QStandardItem* makeitem(const QString& text);

public:
    explicit Window(QWidget *parent = nullptr);
    QStandardItemModel* initializecheckbox(QObject* parent = nullptr);
    QStringList Window::returncheckeditems(QStandardItemModel* model);

};
