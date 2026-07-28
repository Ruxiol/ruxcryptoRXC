// Copyright (c) 2026 The RuxCrypto Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stakingpage.h"
#include "ui_stakingpage.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "walletmodel.h"

#include "miner.h"
#include "util.h"
#include "utilmoneystr.h"
#include "chainparams.h"
#include "wallet/wallet.h"

#include <QHeaderView>
#include <QTableWidgetItem>
#include <QTimer>

StakingPage::StakingPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::StakingPage),
    walletModel(0),
    timer(0)
{
    ui->setupUi(this);

    ui->tableOutputs->setColumnCount(3);
    ui->tableOutputs->horizontalHeader()->setStretchLastSection(true);
    ui->tableOutputs->verticalHeader()->setVisible(false);

    connect(ui->toggleStaking, SIGNAL(clicked()), this, SLOT(toggleStaking()));
}

StakingPage::~StakingPage()
{
    delete ui;
}

void StakingPage::setWalletModel(WalletModel *model)
{
    walletModel = model;
    if (!model)
        return;

    // Two seconds. Nothing here moves faster than a block, and the query walks
    // every output in the wallet.
    if (!timer) {
        timer = new QTimer(this);
        connect(timer, SIGNAL(timeout()), this, SLOT(updateStakingStatus()));
        timer->start(2000);
    }
    updateStakingStatus();
}

void StakingPage::updateStakingStatus()
{
    if (!walletModel || !walletModel->getWallet() || !walletModel->getOptionsModel())
        return;

    const CWallet::StakingStatus st = walletModel->getWallet()->GetStakingStatus();
    const int unit = walletModel->getOptionsModel()->getDisplayUnit();

    ui->labelStatus->setText(QString::fromStdString(st.status));
    ui->labelStatus->setStyleSheet(st.staking ? "QLabel { color: green; }"
                                              : "QLabel { color: #b06000; }");

    ui->labelWeight->setText(QString::number(st.weight));
    ui->labelEligible->setText(BitcoinUnits::formatWithUnit(unit, st.eligibleBalance, false,
                                                           BitcoinUnits::separatorAlways));
    ui->labelDifficulty->setText(QString::number(st.difficulty, 'g', 6));

    if (!st.staking || st.expectedSeconds < 0) {
        ui->labelExpected->setText(tr("n/a"));
    } else {
        ui->labelExpected->setText(GUIUtil::formatDurationStr(st.expectedSeconds));
    }

    // Spelled out rather than left to the release notes: these two numbers are
    // the whole reason a balance can be large and the weight still zero.
    ui->labelRules->setText(tr("a single output of %1 or more, %2 blocks old")
        .arg(BitcoinUnits::formatWithUnit(unit, Params().GetConsensus().nStakeMinAmount, false,
                                          BitcoinUnits::separatorAlways))
        .arg(Params().GetConsensus().nStakeMinConfirmations));

    ui->toggleStaking->setText(st.enabled ? tr("Stop Staking") : tr("Start Staking"));

    ui->tableOutputs->setRowCount((int)st.outputs.size());
    int row = 0;
    for (const CWallet::StakingOutput& out : st.outputs) {
        QTableWidgetItem *amount = new QTableWidgetItem(
            BitcoinUnits::formatWithUnit(unit, out.amount, false, BitcoinUnits::separatorAlways));
        amount->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        QTableWidgetItem *depth = new QTableWidgetItem(QString::number(out.depth));
        depth->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);

        ui->tableOutputs->setItem(row, 0, amount);
        ui->tableOutputs->setItem(row, 1, depth);
        ui->tableOutputs->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(out.address)));
        row++;
    }
    ui->tableOutputs->resizeColumnsToContents();
}

void StakingPage::toggleStaking()
{
    // This run only. Making it stick means editing the config file, and doing
    // that silently on a button press is not something to spring on anyone.
    const bool fWasEnabled = GetBoolArg("-staking", DEFAULT_STAKING);
    ForceSetArg("-staking", fWasEnabled ? "0" : "1");
    updateStakingStatus();
}
