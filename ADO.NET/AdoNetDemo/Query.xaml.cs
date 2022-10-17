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
    /// Interaction logic for Window1.xaml
    /// </summary>

    public partial class Query : Window
    {
        public string sql;

        public bool isOk = false;

        public Query(string _sql)
        {
            InitializeComponent();
            fSQL.Text = _sql;
        }

        private void ButtonOk_Click(object sender, RoutedEventArgs e)
        {
            isOk = true;
            sql = fSQL.Text;
            Close();
        }

        private void ButtonCancel_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }
    }
}
