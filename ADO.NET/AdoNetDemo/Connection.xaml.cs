using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace AdoNetDemo
{
    /// <summary>
    /// Interaction logic for Connection.xaml
    /// </summary>
    public partial class Connection : Window
    {
        public bool isOk = false;
        public string host;
        public string database;
        public string uid;
        public string pwd;


        public Connection(string _host, string _database, string _uid, string _pwd)
        {
            InitializeComponent();
            fHost.Text = _host;
            fDatabase.Text = _database;
            fUID.Text = _uid;
            fPWD.Password = _pwd;
        }

        private void ButtonConnect_Click(object sender, RoutedEventArgs e)
        {
            host = fHost.Text;
            database = fDatabase.Text;
            uid = fUID.Text;
            pwd = fPWD.Password;
            isOk = true;
            Close();
        }
    }
}
