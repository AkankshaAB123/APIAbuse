import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer
} from "recharts";

function RiskChart({ data }) {
  return (
    <div className="chart-card risk-card">

      <div className="chart-header">
        <h2>Risk Distribution</h2>
        <span>Threat severity</span>
      </div>

      <div className="risk-chart-container">
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>

            <Pie
              data={data}
              dataKey="count"
              nameKey="name"
              cx="50%"
              cy="50%"
              outerRadius={100}
              innerRadius={60}
              paddingAngle={3}
            >
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} />
              ))}
            </Pie>

            <Tooltip />

          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="risk-legend">

        {data.map((item) => (
          <div className="risk-legend-item" key={item.name}>
            <span className="risk-dot"></span>

            <span>
              {item.name}: {item.count}
            </span>
          </div>
        ))}

      </div>

    </div>
  );
}

export default RiskChart;