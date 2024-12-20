package military._km.config;

import java.io.IOException;

import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import redis.embedded.RedisServer;

@Configuration
public class EmbeddedRedisConfig {

	private RedisServer redisServer;

	@PostConstruct
	public void init() throws IOException {
		redisServer = new RedisServer(6379);
		redisServer.start();
	}

	@PreDestroy
	public void destroy() throws IOException {
		redisServer.stop();
	}
}
