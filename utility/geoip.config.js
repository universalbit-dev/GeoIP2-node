module.exports = {
  apps: [{
    name: 'geoip-cluster',
    script: './geoip.js',
    exec_mode: 'fork',
    env: {
      NODE_ENV: 'production'
    }
  }]
};
