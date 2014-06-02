﻿namespace MapleShark
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            WeifenLuo.WinFormsUI.Docking.DockPanelSkin dockPanelSkin2 = new WeifenLuo.WinFormsUI.Docking.DockPanelSkin();
            WeifenLuo.WinFormsUI.Docking.AutoHideStripSkin autoHideStripSkin2 = new WeifenLuo.WinFormsUI.Docking.AutoHideStripSkin();
            WeifenLuo.WinFormsUI.Docking.DockPanelGradient dockPanelGradient4 = new WeifenLuo.WinFormsUI.Docking.DockPanelGradient();
            WeifenLuo.WinFormsUI.Docking.TabGradient tabGradient8 = new WeifenLuo.WinFormsUI.Docking.TabGradient();
            WeifenLuo.WinFormsUI.Docking.DockPaneStripSkin dockPaneStripSkin2 = new WeifenLuo.WinFormsUI.Docking.DockPaneStripSkin();
            WeifenLuo.WinFormsUI.Docking.DockPaneStripGradient dockPaneStripGradient2 = new WeifenLuo.WinFormsUI.Docking.DockPaneStripGradient();
            WeifenLuo.WinFormsUI.Docking.TabGradient tabGradient9 = new WeifenLuo.WinFormsUI.Docking.TabGradient();
            WeifenLuo.WinFormsUI.Docking.DockPanelGradient dockPanelGradient5 = new WeifenLuo.WinFormsUI.Docking.DockPanelGradient();
            WeifenLuo.WinFormsUI.Docking.TabGradient tabGradient10 = new WeifenLuo.WinFormsUI.Docking.TabGradient();
            WeifenLuo.WinFormsUI.Docking.DockPaneStripToolWindowGradient dockPaneStripToolWindowGradient2 = new WeifenLuo.WinFormsUI.Docking.DockPaneStripToolWindowGradient();
            WeifenLuo.WinFormsUI.Docking.TabGradient tabGradient11 = new WeifenLuo.WinFormsUI.Docking.TabGradient();
            WeifenLuo.WinFormsUI.Docking.TabGradient tabGradient12 = new WeifenLuo.WinFormsUI.Docking.TabGradient();
            WeifenLuo.WinFormsUI.Docking.DockPanelGradient dockPanelGradient6 = new WeifenLuo.WinFormsUI.Docking.DockPanelGradient();
            WeifenLuo.WinFormsUI.Docking.TabGradient tabGradient13 = new WeifenLuo.WinFormsUI.Docking.TabGradient();
            WeifenLuo.WinFormsUI.Docking.TabGradient tabGradient14 = new WeifenLuo.WinFormsUI.Docking.TabGradient();
            this.mMenu = new System.Windows.Forms.MenuStrip();
            this.mFileMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.mFileImportMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.importJavapropertiesFileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.mFileOpenMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.mFileSeparatorMenu = new System.Windows.Forms.ToolStripSeparator();
            this.mFileQuit = new System.Windows.Forms.ToolStripMenuItem();
            this.mViewMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.mViewSearchMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.mViewDataMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.mViewStructureMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.mViewPropertiesMenu = new System.Windows.Forms.ToolStripMenuItem();
            this.mTimer = new System.Windows.Forms.Timer(this.components);
            this.mImportDialog = new System.Windows.Forms.OpenFileDialog();
            this.mOpenDialog = new System.Windows.Forms.OpenFileDialog();
            this.toolStrip = new System.Windows.Forms.ToolStrip();
            this.openToolStripButton = new System.Windows.Forms.ToolStripButton();
            this.saveToolStripButton = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.mStopStartButton = new System.Windows.Forms.ToolStripButton();
            this.toolStripSeparator2 = new System.Windows.Forms.ToolStripSeparator();
            this.helpToolStripButton = new System.Windows.Forms.ToolStripButton();
            this.mDockPanel = new WeifenLuo.WinFormsUI.Docking.DockPanel();
            this.mMenu.SuspendLayout();
            this.toolStrip.SuspendLayout();
            this.SuspendLayout();
            // 
            // mMenu
            // 
            this.mMenu.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mFileMenu,
            this.mViewMenu});
            this.mMenu.Location = new System.Drawing.Point(0, 0);
            this.mMenu.Name = "mMenu";
            this.mMenu.Size = new System.Drawing.Size(947, 24);
            this.mMenu.TabIndex = 1;
            // 
            // mFileMenu
            // 
            this.mFileMenu.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mFileImportMenu,
            this.importJavapropertiesFileToolStripMenuItem,
            this.mFileOpenMenu,
            this.mFileSeparatorMenu,
            this.mFileQuit});
            this.mFileMenu.Name = "mFileMenu";
            this.mFileMenu.Size = new System.Drawing.Size(37, 20);
            this.mFileMenu.Text = "&File";
            // 
            // mFileImportMenu
            // 
            this.mFileImportMenu.Name = "mFileImportMenu";
            this.mFileImportMenu.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.I)));
            this.mFileImportMenu.Size = new System.Drawing.Size(218, 22);
            this.mFileImportMenu.Text = "&Import";
            this.mFileImportMenu.Click += new System.EventHandler(this.mFileImportMenu_Click);
            // 
            // importJavapropertiesFileToolStripMenuItem
            // 
            this.importJavapropertiesFileToolStripMenuItem.Name = "importJavapropertiesFileToolStripMenuItem";
            this.importJavapropertiesFileToolStripMenuItem.Size = new System.Drawing.Size(218, 22);
            this.importJavapropertiesFileToolStripMenuItem.Text = "Import Java *.properties file";
            this.importJavapropertiesFileToolStripMenuItem.Click += new System.EventHandler(this.importJavapropertiesFileToolStripMenuItem_Click);
            // 
            // mFileOpenMenu
            // 
            this.mFileOpenMenu.Name = "mFileOpenMenu";
            this.mFileOpenMenu.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.O)));
            this.mFileOpenMenu.Size = new System.Drawing.Size(218, 22);
            this.mFileOpenMenu.Text = "&Open";
            this.mFileOpenMenu.Click += new System.EventHandler(this.mFileOpenMenu_Click);
            // 
            // mFileSeparatorMenu
            // 
            this.mFileSeparatorMenu.Name = "mFileSeparatorMenu";
            this.mFileSeparatorMenu.Size = new System.Drawing.Size(215, 6);
            // 
            // mFileQuit
            // 
            this.mFileQuit.Name = "mFileQuit";
            this.mFileQuit.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Alt | System.Windows.Forms.Keys.F4)));
            this.mFileQuit.Size = new System.Drawing.Size(218, 22);
            this.mFileQuit.Text = "&Quit";
            this.mFileQuit.Click += new System.EventHandler(this.mFileQuit_Click);
            // 
            // mViewMenu
            // 
            this.mViewMenu.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mViewSearchMenu,
            this.mViewDataMenu,
            this.mViewStructureMenu,
            this.mViewPropertiesMenu});
            this.mViewMenu.Name = "mViewMenu";
            this.mViewMenu.Size = new System.Drawing.Size(44, 20);
            this.mViewMenu.Text = "&View";
            this.mViewMenu.DropDownOpening += new System.EventHandler(this.mViewMenu_DropDownOpening);
            // 
            // mViewSearchMenu
            // 
            this.mViewSearchMenu.Checked = true;
            this.mViewSearchMenu.CheckOnClick = true;
            this.mViewSearchMenu.CheckState = System.Windows.Forms.CheckState.Checked;
            this.mViewSearchMenu.Name = "mViewSearchMenu";
            this.mViewSearchMenu.ShortcutKeys = System.Windows.Forms.Keys.F9;
            this.mViewSearchMenu.Size = new System.Drawing.Size(152, 22);
            this.mViewSearchMenu.Text = "Sea&rch";
            this.mViewSearchMenu.CheckedChanged += new System.EventHandler(this.mViewSearchMenu_CheckedChanged);
            // 
            // mViewDataMenu
            // 
            this.mViewDataMenu.Checked = true;
            this.mViewDataMenu.CheckOnClick = true;
            this.mViewDataMenu.CheckState = System.Windows.Forms.CheckState.Checked;
            this.mViewDataMenu.Name = "mViewDataMenu";
            this.mViewDataMenu.ShortcutKeys = System.Windows.Forms.Keys.F10;
            this.mViewDataMenu.Size = new System.Drawing.Size(152, 22);
            this.mViewDataMenu.Text = "&Data";
            this.mViewDataMenu.CheckedChanged += new System.EventHandler(this.mViewDataMenu_CheckedChanged);
            // 
            // mViewStructureMenu
            // 
            this.mViewStructureMenu.Checked = true;
            this.mViewStructureMenu.CheckOnClick = true;
            this.mViewStructureMenu.CheckState = System.Windows.Forms.CheckState.Checked;
            this.mViewStructureMenu.Name = "mViewStructureMenu";
            this.mViewStructureMenu.ShortcutKeys = System.Windows.Forms.Keys.F11;
            this.mViewStructureMenu.Size = new System.Drawing.Size(152, 22);
            this.mViewStructureMenu.Text = "&Structure";
            this.mViewStructureMenu.CheckedChanged += new System.EventHandler(this.mViewStructureMenu_CheckedChanged);
            // 
            // mViewPropertiesMenu
            // 
            this.mViewPropertiesMenu.Checked = true;
            this.mViewPropertiesMenu.CheckOnClick = true;
            this.mViewPropertiesMenu.CheckState = System.Windows.Forms.CheckState.Checked;
            this.mViewPropertiesMenu.Name = "mViewPropertiesMenu";
            this.mViewPropertiesMenu.ShortcutKeys = System.Windows.Forms.Keys.F12;
            this.mViewPropertiesMenu.Size = new System.Drawing.Size(152, 22);
            this.mViewPropertiesMenu.Text = "&Properties";
            this.mViewPropertiesMenu.CheckedChanged += new System.EventHandler(this.mViewPropertiesMenu_CheckedChanged);
            // 
            // mTimer
            // 
            this.mTimer.Interval = 300;
            this.mTimer.Tick += new System.EventHandler(this.mTimer_Tick);
            // 
            // mImportDialog
            // 
            this.mImportDialog.Filter = "PCap Files|*.pcap";
            this.mImportDialog.ReadOnlyChecked = true;
            this.mImportDialog.RestoreDirectory = true;
            this.mImportDialog.Title = "Import";
            // 
            // mOpenDialog
            // 
            this.mOpenDialog.Filter = "MapleShark Binary Files|*.msb";
            this.mOpenDialog.Multiselect = true;
            this.mOpenDialog.ReadOnlyChecked = true;
            this.mOpenDialog.RestoreDirectory = true;
            this.mOpenDialog.Title = "Open";
            // 
            // toolStrip
            // 
            this.toolStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.openToolStripButton,
            this.saveToolStripButton,
            this.toolStripSeparator1,
            this.mStopStartButton,
            this.toolStripSeparator2,
            this.helpToolStripButton});
            this.toolStrip.Location = new System.Drawing.Point(0, 24);
            this.toolStrip.Name = "toolStrip";
            this.toolStrip.Size = new System.Drawing.Size(947, 25);
            this.toolStrip.TabIndex = 11;
            this.toolStrip.Text = "ToolStrip";
            // 
            // openToolStripButton
            // 
            this.openToolStripButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.openToolStripButton.Image = ((System.Drawing.Image)(resources.GetObject("openToolStripButton.Image")));
            this.openToolStripButton.ImageTransparentColor = System.Drawing.Color.Black;
            this.openToolStripButton.Name = "openToolStripButton";
            this.openToolStripButton.Size = new System.Drawing.Size(23, 22);
            this.openToolStripButton.Text = "Open";
            this.openToolStripButton.Click += new System.EventHandler(this.mFileOpenMenu_Click);
            // 
            // saveToolStripButton
            // 
            this.saveToolStripButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.saveToolStripButton.Image = ((System.Drawing.Image)(resources.GetObject("saveToolStripButton.Image")));
            this.saveToolStripButton.ImageTransparentColor = System.Drawing.Color.Black;
            this.saveToolStripButton.Name = "saveToolStripButton";
            this.saveToolStripButton.Size = new System.Drawing.Size(23, 22);
            this.saveToolStripButton.Text = "Save";
            this.saveToolStripButton.Click += new System.EventHandler(this.saveToolStripButton_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(6, 25);
            // 
            // mStopStartButton
            // 
            this.mStopStartButton.Image = global::MapleShark.Properties.Resources.Button_Blank_Red_icon;
            this.mStopStartButton.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.mStopStartButton.Name = "mStopStartButton";
            this.mStopStartButton.Size = new System.Drawing.Size(94, 22);
            this.mStopStartButton.Text = "Stop sniffing";
            this.mStopStartButton.Click += new System.EventHandler(this.toolStripButton1_Click);
            // 
            // toolStripSeparator2
            // 
            this.toolStripSeparator2.Name = "toolStripSeparator2";
            this.toolStripSeparator2.Size = new System.Drawing.Size(6, 25);
            // 
            // helpToolStripButton
            // 
            this.helpToolStripButton.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Image;
            this.helpToolStripButton.Image = ((System.Drawing.Image)(resources.GetObject("helpToolStripButton.Image")));
            this.helpToolStripButton.ImageTransparentColor = System.Drawing.Color.Black;
            this.helpToolStripButton.Name = "helpToolStripButton";
            this.helpToolStripButton.Size = new System.Drawing.Size(23, 22);
            this.helpToolStripButton.Text = "Help";
            this.helpToolStripButton.Click += new System.EventHandler(this.helpToolStripButton_Click);
            // 
            // mDockPanel
            // 
            this.mDockPanel.ActiveAutoHideContent = null;
            this.mDockPanel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.mDockPanel.DockBackColor = System.Drawing.SystemColors.ControlDark;
            this.mDockPanel.DockBottomPortion = 0.3D;
            this.mDockPanel.DockLeftPortion = 0.3D;
            this.mDockPanel.DockRightPortion = 0.3D;
            this.mDockPanel.DockTopPortion = 75D;
            this.mDockPanel.Location = new System.Drawing.Point(0, 24);
            this.mDockPanel.Name = "mDockPanel";
            this.mDockPanel.Size = new System.Drawing.Size(947, 449);
            dockPanelGradient4.EndColor = System.Drawing.SystemColors.ControlLight;
            dockPanelGradient4.StartColor = System.Drawing.SystemColors.ControlLight;
            autoHideStripSkin2.DockStripGradient = dockPanelGradient4;
            tabGradient8.EndColor = System.Drawing.SystemColors.ControlLight;
            tabGradient8.StartColor = System.Drawing.SystemColors.ControlLight;
            tabGradient8.TextColor = System.Drawing.SystemColors.ControlDarkDark;
            autoHideStripSkin2.TabGradient = tabGradient8;
            dockPanelSkin2.AutoHideStripSkin = autoHideStripSkin2;
            tabGradient9.EndColor = System.Drawing.SystemColors.ControlLightLight;
            tabGradient9.StartColor = System.Drawing.SystemColors.ControlLightLight;
            tabGradient9.TextColor = System.Drawing.SystemColors.ControlText;
            dockPaneStripGradient2.ActiveTabGradient = tabGradient9;
            dockPanelGradient5.EndColor = System.Drawing.SystemColors.Control;
            dockPanelGradient5.StartColor = System.Drawing.SystemColors.Control;
            dockPaneStripGradient2.DockStripGradient = dockPanelGradient5;
            tabGradient10.EndColor = System.Drawing.SystemColors.ControlLight;
            tabGradient10.StartColor = System.Drawing.SystemColors.ControlLight;
            tabGradient10.TextColor = System.Drawing.SystemColors.ControlText;
            dockPaneStripGradient2.InactiveTabGradient = tabGradient10;
            dockPaneStripSkin2.DocumentGradient = dockPaneStripGradient2;
            tabGradient11.EndColor = System.Drawing.SystemColors.ActiveCaption;
            tabGradient11.LinearGradientMode = System.Drawing.Drawing2D.LinearGradientMode.Vertical;
            tabGradient11.StartColor = System.Drawing.SystemColors.GradientActiveCaption;
            tabGradient11.TextColor = System.Drawing.SystemColors.ActiveCaptionText;
            dockPaneStripToolWindowGradient2.ActiveCaptionGradient = tabGradient11;
            tabGradient12.EndColor = System.Drawing.SystemColors.Control;
            tabGradient12.StartColor = System.Drawing.SystemColors.Control;
            tabGradient12.TextColor = System.Drawing.SystemColors.ControlText;
            dockPaneStripToolWindowGradient2.ActiveTabGradient = tabGradient12;
            dockPanelGradient6.EndColor = System.Drawing.SystemColors.Control;
            dockPanelGradient6.StartColor = System.Drawing.SystemColors.Control;
            dockPaneStripToolWindowGradient2.DockStripGradient = dockPanelGradient6;
            tabGradient13.EndColor = System.Drawing.SystemColors.GradientInactiveCaption;
            tabGradient13.LinearGradientMode = System.Drawing.Drawing2D.LinearGradientMode.Vertical;
            tabGradient13.StartColor = System.Drawing.SystemColors.GradientInactiveCaption;
            tabGradient13.TextColor = System.Drawing.SystemColors.ControlText;
            dockPaneStripToolWindowGradient2.InactiveCaptionGradient = tabGradient13;
            tabGradient14.EndColor = System.Drawing.Color.Transparent;
            tabGradient14.StartColor = System.Drawing.Color.Transparent;
            tabGradient14.TextColor = System.Drawing.SystemColors.ControlDarkDark;
            dockPaneStripToolWindowGradient2.InactiveTabGradient = tabGradient14;
            dockPaneStripSkin2.ToolWindowGradient = dockPaneStripToolWindowGradient2;
            dockPanelSkin2.DockPaneStripSkin = dockPaneStripSkin2;
            this.mDockPanel.Skin = dockPanelSkin2;
            this.mDockPanel.TabIndex = 4;
            this.mDockPanel.ActiveDocumentChanged += new System.EventHandler(this.mDockPanel_ActiveDocumentChanged);
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(947, 473);
            this.Controls.Add(this.toolStrip);
            this.Controls.Add(this.mDockPanel);
            this.Controls.Add(this.mMenu);
            this.DoubleBuffered = true;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.IsMdiContainer = true;
            this.MainMenuStrip = this.mMenu;
            this.Name = "MainForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "ElShark";
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.MainForm_FormClosed);
            this.Load += new System.EventHandler(this.MainForm_Load);
            this.mMenu.ResumeLayout(false);
            this.mMenu.PerformLayout();
            this.toolStrip.ResumeLayout(false);
            this.toolStrip.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.MenuStrip mMenu;
        private System.Windows.Forms.ToolStripMenuItem mFileMenu;
        private System.Windows.Forms.ToolStripMenuItem mFileImportMenu;
        private System.Windows.Forms.ToolStripMenuItem mFileOpenMenu;
        private System.Windows.Forms.Timer mTimer;
        private System.Windows.Forms.OpenFileDialog mImportDialog;
        private System.Windows.Forms.OpenFileDialog mOpenDialog;
        private WeifenLuo.WinFormsUI.Docking.DockPanel mDockPanel;
        private System.Windows.Forms.ToolStripMenuItem mViewMenu;
        private System.Windows.Forms.ToolStripMenuItem mViewPropertiesMenu;
        private System.Windows.Forms.ToolStripMenuItem mViewStructureMenu;
        private System.Windows.Forms.ToolStripSeparator mFileSeparatorMenu;
        private System.Windows.Forms.ToolStripMenuItem mFileQuit;
        private System.Windows.Forms.ToolStripMenuItem mViewDataMenu;
        private System.Windows.Forms.ToolStripMenuItem mViewSearchMenu;
        private System.Windows.Forms.ToolStrip toolStrip;
        private System.Windows.Forms.ToolStripButton openToolStripButton;
        private System.Windows.Forms.ToolStripButton saveToolStripButton;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.ToolStripButton mStopStartButton;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator2;
        private System.Windows.Forms.ToolStripButton helpToolStripButton;
        private System.Windows.Forms.ToolStripMenuItem importJavapropertiesFileToolStripMenuItem;
    }
}

