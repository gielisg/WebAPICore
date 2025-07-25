
using System.Collections.Generic;
using System.Data;
using Dapper;
using Microsoft.Data.SqlClient;

namespace DataAccess
{
    public class DataAccessService
    {
        public static IEnumerable<dynamic> ExecuteSql(string dsn, string sql, object parameters)
        {
            using (var connection = new SqlConnection(dsn))
            {
                return connection.Query(sql, parameters);
            }
        }
    }
}
