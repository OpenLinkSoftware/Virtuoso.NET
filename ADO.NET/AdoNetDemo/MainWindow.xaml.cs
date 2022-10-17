using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using OpenLink.Data.Virtuoso;
using System.Data;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace AdoNetDemo
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        VirtuosoConnection conn = null;
        string host = "localhost:1111";
        string database = "";
        string uid = "dba";
        string pwd = "";
        string sql = "select * from orders";
        const string titleBase = "ADO.NET Demo ";

        public MainWindow()
        {
            InitializeComponent();

            AppDomain.CurrentDomain.UnhandledException += CurrentDomain_UnhandledException;
            Title = titleBase;
            updateMenuState(false);
        }

        void CurrentDomain_UnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            string message = "Exception: " + e.ExceptionObject;
            MessageBox.Show(message);
        }

        private void MenuExit_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void MenuAbout_Click(object sender, RoutedEventArgs e)
        {

        }


        private void MenuExecute_Click(object sender, RoutedEventArgs e)
        {
            if (conn == null)
                return;

            var dlg = new Query(sql);
            dlg.ShowDialog();
            if (dlg.isOk)
            {
                sql = dlg.sql;
                VirtuosoCommand cmd = null;
                try
                {
                    cmd = conn.CreateCommand();
                    cmd.CommandText = sql;
                    VirtuosoDataAdapter adapter = new VirtuosoDataAdapter();
                    adapter.SelectCommand = cmd;
                    DataSet dataset = new DataSet();
                    adapter.Fill(dataset);

                    var tb = dataset.Tables["table"];

                    var _gridView = new GridView();
                    foreach (DataColumn col in tb.Columns)
                    {
                        var maxLen = col.MaxLength;
                        if (maxLen <= 0 || maxLen > 100)
                            maxLen = 100;

                        var gvc = new GridViewColumn();
                        gvc.DisplayMemberBinding = new Binding(col.ColumnName);
                        gvc.Header = col.ColumnName;
                        gvc.Width = maxLen;
                        _gridView.Columns.Add(gvc);
                    }
                    lvData.View = _gridView;
                    lvData.ItemsSource = tb.DefaultView;
                    lvData.MouseDoubleClick += LvData_MouseDoubleClick;

                }
                catch (Exception ex)
                {
                    string message = "Exception: " + ex;
                    MessageBox.Show(message);
                } finally
                {
                    if (cmd != null)
                        try
                        {
                            cmd.Dispose();
                        }
                        catch (Exception) { }
                }
            }
        }


        private void LvData_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            HitTestResult hitTest = VisualTreeHelper.HitTest(lvData, e.GetPosition(lvData));
            var textBlock = hitTest.VisualHit as TextBlock;
            if (textBlock != null)
            {
                var txt = textBlock.Text;
                if (txt.StartsWith("http://") || txt.StartsWith("https://"))
                    OpenBrowser(txt);
            }
        }

        private void MenuClose_Click(object sender, RoutedEventArgs e)
        {
            if (conn != null)
                try
                {
                    conn.Close();
                }
                catch (Exception) { }
            Title = titleBase;
            lvData.View = null;
            lvData.ItemsSource = null;
            updateMenuState(false);
        }

        private void MenuOpen_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new Connection(host, database, uid, pwd);
            dlg.ShowDialog();
            if (dlg.isOk)
            {
                if (conn != null)
                    try
                    {
                        conn.Close();
                    }
                    catch (Exception) { }
                Title = titleBase;
                conn = null;

                host = dlg.host;
                uid = dlg.uid;
                pwd = dlg.pwd;
                database = dlg.database;

                try
                {
                    conn = new VirtuosoConnection();
                    conn.ConnectionString = $"Host=\"{host}\";UID=\"{uid}\";PWD=\"{pwd}\"";
                    if (!string.IsNullOrWhiteSpace(database))
                        conn.ConnectionString = conn.ConnectionString + $";Database=\"{database}\"";
                    conn.Open();
                    this.Title = titleBase + $" | Connected {host}";
                }
                catch (Exception ex)
                {
                    string message = "Exception: " + ex;
                    MessageBox.Show(message);
                }
                updateMenuState(true);
            }
        }

        private void updateMenuState(bool connected)
        {
            if (connected)
            {
                mnClose.IsEnabled = true;
                mnSQL.IsEnabled = true;
            } else
            {
                mnClose.IsEnabled = false;
                mnSQL.IsEnabled = false;
            }
        }


        public void OpenBrowser(string url)
        {
            try
            {
                Process.Start(url);
            }
            catch
            {
                // hack because of this: https://github.com/dotnet/corefx/issues/10361
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    url = url.Replace("&", "^&");
                    Process.Start(new ProcessStartInfo("cmd", $"/c start {url}") { CreateNoWindow = true });
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    Process.Start("xdg-open", url);
                }
                else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                {
                    Process.Start("open", url);
                }
                else
                {
                    throw;
                }
            }
        }


    }
}
