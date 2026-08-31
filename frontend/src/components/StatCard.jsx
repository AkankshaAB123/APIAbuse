function StatCard({ title, value, description, icon, type }) {
  return (
    <div className={`stat-card stat-${type}`}>

      <div className="stat-card-top">

        <div>
          <p className="stat-title">
            {title}
          </p>

          <h2 className="stat-value">
            {value.toLocaleString()}
          </h2>
        </div>

        <div className="stat-icon">
          {icon}
        </div>

      </div>

      <p className="stat-description">
        {description}
      </p>

    </div>
  );
}

export default StatCard;