import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer
} from "recharts";

function RiskChart({ data }) {
  const colors = [
    "#22C55E", // Green - Low
    "#F59E0B", // Orange - Medium
    "#F97316", // Orange-red - High
    "#EF4444", // Red - Critical
    "#EC4899", // Pink - Extra category
    "#8B5CF6"  // Purple - Extra category
  ];

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
                <Cell
                  key={`cell-${index}`}
                  fill={colors[index % colors.length]}
                  stroke="#0b1022"
                  strokeWidth={2}
                />
              ))}
            </Pie>

            <Tooltip
              contentStyle={{
                backgroundColor: "#11172a",
                border: "1px solid #39446f",
                borderRadius: "10px",
                color: "#f5f7ff",
                boxShadow: "0 8px 25px rgba(0, 0, 0, 0.35)"
              }}
              labelStyle={{
                color: "#ffffff",
                fontWeight: 600
              }}
              itemStyle={{
                color: "#c4b5fd"
              }}
            />

          </PieChart>
        </ResponsiveContainer>
      </div>

      <div className="risk-legend">

        {data.map((item, index) => (
          <div className="risk-legend-item" key={item.name}>

            <span
              className="risk-dot"
              style={{
                backgroundColor: colors[index % colors.length],
                boxShadow: `0 0 8px ${colors[index % colors.length]}`
              }}
            ></span>

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